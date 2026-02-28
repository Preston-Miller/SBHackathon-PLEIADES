import json
import os
import re
from anthropic import Anthropic

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


def _default_enrich(f: dict, i: int) -> dict:
    out = dict(f)
    out["order"] = i
    out["risk_explanation"] = "Fix this issue to reduce security risk."
    out["fix_steps"] = ["Address the finding as described in the evidence."]
    out["verify"] = "Confirm the issue is resolved."
    return out


def _fallback(raw_findings: list[dict]) -> dict:
    order = {"secrets": 0, "env": 1, "dependencies": 2}
    sorted_f = sorted(
        raw_findings,
        key=lambda x: (order.get(x.get("scanner", ""), 99), x.get("path", "")),
    )
    top5 = sorted_f[:5]
    return {
        "findings": [_default_enrich(f, i) for i, f in enumerate(top5)],
        "developer_summary": None,
    }


def _extract_json_block(text: str) -> dict | None:
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if not match:
        return None
    try:
        return json.loads(match.group(1).strip())
    except json.JSONDecodeError:
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
        "order": plan.get("finding_id", 0),
        "risk_explanation": risk,
        "fix_steps": steps,
        "verify": plan.get("verification_steps") or "Confirm the issue is resolved.",
    }


def run(raw_findings: list[dict]) -> dict:
    if not raw_findings:
        return {"findings": [], "developer_summary": None}
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return _fallback(raw_findings)
    payload = json.dumps(raw_findings, indent=2)
    user_msg = f"Raw findings (finding_id = 0-based index):\n{payload}\n\nReturn Section 1 (Markdown developer summary), then Section 2 (single ```json code block with remediation_plan only, max 5 items)."
    try:
        client = Anthropic(api_key=key)
        msg = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=4096,
            system=SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        text = msg.content[0].text if msg.content else ""
    except Exception:
        return _fallback(raw_findings)
    data = _extract_json_block(text)
    if not data or "remediation_plan" not in data:
        return _fallback(raw_findings)
    plan_list = data["remediation_plan"]
    if not isinstance(plan_list, list) or len(plan_list) == 0:
        return _fallback(raw_findings)
    summary = None
    if "```" in text:
        summary = text.split("```")[0].strip()
        if summary:
            summary = summary.strip()
    out = []
    for p in plan_list[:5]:
        fid = p.get("finding_id", 0)
        if not isinstance(fid, int) or fid < 0 or fid >= len(raw_findings):
            continue
        out.append(_map_plan_to_finding(raw_findings[fid], p))
    out.sort(key=lambda x: x.get("order", 999))
    if not out:
        return _fallback(raw_findings)
    return {"findings": out, "developer_summary": summary}
