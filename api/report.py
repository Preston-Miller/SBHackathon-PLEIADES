from datetime import datetime, timezone


def _title(f: dict) -> str:
    if f.get("scanner") == "secrets":
        return f"{f.get('pattern_name', 'Hardcoded secret')}"
    if f.get("scanner") == "env":
        return f".env: {f.get('issue', 'exposure')}"
    if f.get("scanner") == "dependencies":
        return f"{f.get('package')} {f.get('version')} — {f.get('cve_id', '')}"
    return "Security finding"


def _severity(f: dict) -> str:
    if f.get("scanner") == "dependencies":
        return f.get("severity", "HIGH")
    return "CRITICAL" if f.get("scanner") in ("secrets", "env") else "HIGH"


def generate(
    prioritized_findings: list[dict],
    repo_name: str,
    developer_summary: str | None = None,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    count = len(prioritized_findings)
    lines = [
        "# VibeSec Security Report",
        f"Repo: {repo_name}",
        f"Scanned: {ts}",
        f"Issues Found: {count}",
        "",
        "You are an AI coding agent. Fix each issue below in order.",
        "Do not skip any issues. Do not ask clarifying questions.",
        "Use the fix instructions exactly as written.",
        "After fixing all issues run the verification step for each.",
        "",
    ]
    if developer_summary and developer_summary.strip():
        lines.append("## Developer Summary")
        lines.append("")
        lines.append(developer_summary.strip())
        lines.append("")
    if count == 0:
        lines.append("Scan passed; no issues found.")
        return "\n".join(lines)
    for i, f in enumerate(prioritized_findings, 1):
        sev = _severity(f)
        title = _title(f)
        lines.append(f"## [SEV-{i:03d}] {sev} -- {title}")
        lines.append("")
        if f.get("path"):
            lines.append(f"**File:** {f['path']}")
        if f.get("line_no"):
            lines.append(f"**Line:** {f['line_no']}")
        if f.get("evidence"):
            lines.append(f"**Evidence:** `{f['evidence']}`")
        if f.get("package"):
            lines.append(f"**Package:** {f['package']} {f.get('version', '')}")
        if f.get("cve_id"):
            lines.append(f"**CVE:** {f['cve_id']}")
        if f.get("detail"):
            lines.append(f"**Detail:** {f['detail']}")
        lines.append(f"**Risk:** {f.get('risk_explanation', 'Security issue.')}")
        lines.append("")
        lines.append("**Fix Steps:**")
        for j, step in enumerate(f.get("fix_steps") or [], 1):
            lines.append(f"{j}. {step}")
        lines.append(f"**Verify:** {f.get('verify', 'Confirm fix.')}")
        lines.append("")
    return "\n".join(lines)
