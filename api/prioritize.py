import json
import os
from anthropic import Anthropic

SYSTEM = (
    "You are a security triage expert reviewing findings for a solo developer's project. "
    "Order these findings by real world risk. Write explanations in plain English a non-technical "
    "developer can understand. Be specific and direct. Do not add issues not found by the scanners. "
    "Do not use the words consider, might, or could."
)


def _default_enrich(f: dict, i: int) -> dict:
    out = dict(f)
    out["order"] = i
    out["risk_explanation"] = "Fix this issue to reduce security risk."
    out["fix_steps"] = ["Address the finding as described in the evidence."]
    out["verify"] = "Confirm the issue is resolved."
    return out


def run(raw_findings: list[dict]) -> list[dict]:
    if not raw_findings:
        return []
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        order = {"secrets": 0, "env": 1, "dependencies": 2}
        return [
            _default_enrich(f, i)
            for i, f in enumerate(
                sorted(raw_findings, key=lambda x: (order.get(x.get("scanner", ""), 99), x.get("path", "")))
            )
        ]
    try:
        client = Anthropic(api_key=key)
        payload = json.dumps(raw_findings, indent=2)
        msg = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=4096,
            system=SYSTEM,
            messages=[{
                "role": "user",
                "content": f"Return a JSON array. For each finding, include: finding_id (index 0-based), order, risk_explanation, fix_steps (array of strings), verify (string). Raw findings:\n{payload}",
            }],
        )
        text = msg.content[0].text if msg.content else "[]"
        start = text.find("[")
        if start >= 0:
            text = text[start:]
        end = text.rfind("]") + 1
        if end > start:
            parsed = json.loads(text[:end])
        else:
            parsed = []
    except Exception:
        parsed = []
    if not parsed or len(parsed) != len(raw_findings):
        return [_default_enrich(f, i) for i, f in enumerate(raw_findings)]
    by_id = {p.get("finding_id", i): p for i, p in enumerate(parsed)}
    out = []
    for i, f in enumerate(raw_findings):
        p = by_id.get(i, {})
        out.append({
            **f,
            "order": p.get("order", i),
            "risk_explanation": p.get("risk_explanation", _default_enrich(f, i)["risk_explanation"]),
            "fix_steps": p.get("fix_steps", _default_enrich(f, i)["fix_steps"]),
            "verify": p.get("verify", _default_enrich(f, i)["verify"]),
        })
    out.sort(key=lambda x: x.get("order", 999))
    return out
