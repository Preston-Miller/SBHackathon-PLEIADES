import json
import logging
import os
import re
from openai import OpenAI

SYSTEM = """You are a senior application security engineer reviewing automated scanner findings for a solo developer's project.

Task:
- Identify and sort findings by real-world risk (likelihood × impact).
- Return at most the top 5 highest-risk findings.
- If fewer than 5 exist, return only those present.
- Do not invent findings.
- Assume the application is internet-facing.

Output Format (Strict):
Your response must contain exactly two sections:
1. A Markdown-formatted developer summary (plain English, non-technical). For each finding include: Title, What this is, How it would be exploited, Business impact. Do not use: consider, might, could.
2. A single fenced JSON code block containing ONLY the remediation plan. No markdown outside the block. No text after the JSON block.

JSON schema for the remediation_plan:
{
  "remediation_plan": [
    {
      "finding_id": 0,
      "title": "",
      "root_cause": "",
      "exploitation_path": "",
      "required_changes": {
        "files_to_modify": [],
        "change_type": "",
        "implementation_instructions": ""
      },
      "acceptance_criteria": "",
      "verification_steps": ""
    }
  ]
}
Rules: Valid JSON only. No trailing commas. No comments. Maximum 5 findings. finding_id is the 0-based index of the finding in the raw findings array."""

logger = logging.getLogger(__name__)
_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "owasp_mapping.json")
_DEFAULT_MODEL_CANDIDATES = [
    "gpt-4o-mini",
    "gpt-4.1-mini",
    "gpt-4o",
]


def _load_owasp_mapping() -> dict:
    try:
        with open(_MAPPING_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_OWASP_MAPPING = _load_owasp_mapping()


def _mapping_entry(finding: dict) -> dict:
    scanner = finding.get("scanner", "")
    issue = finding.get("issue", "")
    pattern_name = finding.get("pattern_name", "")
    by_scanner = _OWASP_MAPPING.get("by_scanner", {})
    scanner_map = by_scanner.get(scanner, {}) if isinstance(by_scanner, dict) else {}
    by_issue = scanner_map.get("by_issue", {}) if isinstance(scanner_map, dict) else {}
    by_pattern = scanner_map.get("by_pattern_name", {}) if isinstance(scanner_map, dict) else {}
    if issue and isinstance(by_issue, dict) and isinstance(by_issue.get(issue), dict):
        return by_issue[issue]
    if pattern_name and isinstance(by_pattern, dict) and isinstance(by_pattern.get(pattern_name), dict):
        return by_pattern[pattern_name]
    if isinstance(scanner_map, dict) and isinstance(scanner_map.get("default"), dict):
        return scanner_map["default"]
    default_map = _OWASP_MAPPING.get("default", {})
    return default_map if isinstance(default_map, dict) else {}


def _owasp_fields(finding: dict) -> dict:
    entry = _mapping_entry(finding)
    refs = [r for r in (entry.get("owasp_refs") or []) if isinstance(r, str) and r.strip()]
    requirements = [r for r in (entry.get("standard_fix_requirements") or []) if isinstance(r, str) and r.strip()]
    return {
        "owasp_category": entry.get("owasp_category", "General Secure Coding"),
        "owasp_refs": refs,
        "standard_fix_requirements": requirements,
        "owasp_mapping_version": _OWASP_MAPPING.get("mapping_version", "unknown"),
        "owasp_mapping_last_reviewed": _OWASP_MAPPING.get("last_reviewed", "unknown"),
    }


def _default_enrich(f: dict, i: int) -> dict:
    out = dict(f)
    out.update(_owasp_fields(f))
    out["order"] = i
    out["risk_explanation"] = "Fix this issue to reduce security risk."
    out["fix_steps"] = ["Address the finding as described in the evidence."]
    out["verify"] = "Confirm the issue is resolved."
    return out


def _fallback(
    raw_findings: list[dict],
    reason: str,
    model: str | None = None,
    reason_detail: str | None = None,
) -> dict:
    order = {"secrets": 0, "env": 1, "dependencies": 2}
    sorted_f = sorted(
        raw_findings,
        key=lambda x: (order.get(x.get("scanner", ""), 99), x.get("path", "")),
    )
    top5 = sorted_f[:5]
    return {
        "findings": [_default_enrich(f, i) for i, f in enumerate(top5)],
        "developer_summary": None,
        "analysis_meta": {
            "path": "fallback",
            "reason": reason,
            "reason_detail": reason_detail,
            "model": model,
            "raw_findings": len(raw_findings),
            "mapped_findings": len(top5),
        },
    }


def _extract_json_block(text: str) -> dict | None:
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass
    # Fallback: model sometimes returns plain JSON without fences.
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _map_plan_to_finding(raw: dict, plan: dict) -> dict:
    rc = plan.get("required_changes") or {}
    instructions = rc.get("implementation_instructions") or ""
    steps = [s.strip() for s in instructions.split("\n") if s.strip()]
    if not steps:
        steps = ["Address the finding as described in the evidence."]
    risk = plan.get("root_cause") or ""
    if plan.get("exploitation_path"):
        risk = f"{risk} {plan['exploitation_path']}".strip()
    if not risk:
        risk = "Fix this issue to reduce security risk."
    return {
        **raw,
        **_owasp_fields(raw),
        "order": plan.get("finding_id", 0),
        "risk_explanation": risk,
        "fix_steps": steps,
        "verify": plan.get("verification_steps") or "Confirm the issue is resolved.",
    }


def run(raw_findings: list[dict]) -> dict:
    if not raw_findings:
        return {
            "findings": [],
            "developer_summary": None,
            "analysis_meta": {
                "path": "no_findings",
                "reason": "no_raw_findings",
                "model": None,
                "raw_findings": 0,
                "mapped_findings": 0,
            },
        }
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        logger.warning("prioritize: OPENAI_API_KEY is missing; using fallback")
        return _fallback(raw_findings, reason="missing_api_key", model=None)
    configured_model = os.environ.get("OPENAI_MODEL", "").strip()
    candidates = [configured_model] if configured_model else list(_DEFAULT_MODEL_CANDIDATES)
    payload = json.dumps(raw_findings, indent=2)
    user_msg = f"Raw findings (finding_id = 0-based index):\n{payload}\n\nReturn Section 1 (Markdown developer summary), then Section 2 (single ```json code block with remediation_plan only, max 5 items)."
    key = key.strip().strip('"').strip("'")
    client = OpenAI(api_key=key)
    text = ""
    model = None
    last_error_detail = None
    for candidate in candidates:
        try:
            msg = client.chat.completions.create(
                model=candidate,
                temperature=0,
                max_tokens=4096,
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
            )
            text = (msg.choices[0].message.content or "").strip()
            model = candidate
            break
        except Exception as e:
            detail = f"{type(e).__name__}: {str(e)}".strip()
            if len(detail) > 280:
                detail = detail[:280] + "..."
            last_error_detail = detail or "unknown_error"
            logger.exception("prioritize: OpenAI request failed for model=%s: %s", candidate, e)
    if model is None:
        return _fallback(
            raw_findings,
            reason="openai_request_failed",
            model=",".join(candidates),
            reason_detail=last_error_detail,
        )
    data = _extract_json_block(text)
    if not data or "remediation_plan" not in data:
        preview = text[:600].replace("\n", "\\n")
        logger.warning("prioritize: unable to parse remediation_plan JSON; response preview=%s", preview)
        return _fallback(raw_findings, reason="parse_failed_or_missing_remediation_plan", model=model)
    plan_list = data["remediation_plan"]
    if not isinstance(plan_list, list) or len(plan_list) == 0:
        logger.warning("prioritize: remediation_plan missing/empty after parse")
        return _fallback(raw_findings, reason="empty_remediation_plan", model=model)
    summary = None
    if "```" in text:
        summary = text.split("```")[0].strip()
        if summary:
            summary = summary.strip()
    out = []
    for p in plan_list[:5]:
        raw_fid = p.get("finding_id", 0)
        try:
            fid = int(raw_fid)
        except Exception:
            logger.warning("prioritize: invalid finding_id=%r in remediation_plan item", raw_fid)
            continue
        if fid < 0 or fid >= len(raw_findings):
            logger.warning(
                "prioritize: finding_id out of range=%s (findings=%s)",
                fid,
                len(raw_findings),
            )
            continue
        out.append(_map_plan_to_finding(raw_findings[fid], p))
    out.sort(key=lambda x: x.get("order", 999))
    if not out:
        logger.warning("prioritize: no valid remediation items after mapping; using fallback")
        return _fallback(raw_findings, reason="no_valid_finding_ids_from_plan", model=model)
    return {
        "findings": out,
        "developer_summary": summary,
        "analysis_meta": {
            "path": "openai",
            "reason": "ok",
            "model": model,
            "raw_findings": len(raw_findings),
            "raw_plan_items": len(plan_list),
            "mapped_findings": len(out),
            "has_developer_summary": bool(summary and summary.strip()),
        },
    }
