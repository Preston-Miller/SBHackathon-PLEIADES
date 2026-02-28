import json
import re
import httpx

OSV_URL = "https://api.osv.dev/v1/query"
HIGH_SEV = {"CRITICAL", "HIGH"}


def _parse_requirements(content: str) -> list[tuple[str, str]]:
    out = []
    for line in content.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line:
            continue
        m = re.match(r"([a-zA-Z0-9_-]+)\s*==\s*(\S+)", line)
        if m:
            out.append((m.group(1), m.group(2)))
        else:
            m2 = re.match(r"([a-zA-Z0-9_-]+)\s*(\S*)", line)
            if m2 and not line.startswith("-"):
                out.append((m2.group(1), m2.group(2) or "0.0.0"))
    return out


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    out = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return out
    for key in ("dependencies", "devDependencies"):
        deps = data.get(key) or {}
        for name, ver in deps.items():
            if isinstance(ver, str):
                ver = re.sub(r"^[\^~]", "", ver.strip())
            else:
                ver = str(ver)
            out.append((name, ver or "0.0.0"))
    return out


def _query_osv(pkg: str, ver: str, ecosystem: str) -> list[dict]:
    try:
        r = httpx.post(
            OSV_URL,
            json={"package": {"name": pkg, "ecosystem": ecosystem}, "version": ver},
            timeout=15.0,
        )
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    vulns = data.get("vulns") or []
    out = []
    for v in vulns:
        sev = (v.get("database_specific") or {}).get("severity", "").upper()
        if sev not in HIGH_SEV:
            continue
        vid = v.get("id", "")
        if "CVE-" not in vid:
            continue
        summary = (v.get("summary") or v.get("details") or "")[:200]
        out.append({"id": vid, "severity": sev, "summary": summary})
    return out


def scan(files: list[dict]) -> list[dict]:
    findings = []
    req_file = next((f for f in files if f.get("path", "").endswith("requirements.txt")), None)
    pkg_file = next((f for f in files if f.get("path", "").endswith("package.json")), None)
    if req_file:
        for pkg, ver in _parse_requirements(req_file["content"]):
            for v in _query_osv(pkg, ver, "PyPI"):
                findings.append({
                    "scanner": "dependencies",
                    "package": pkg,
                    "version": ver,
                    "cve_id": v["id"],
                    "severity": v["severity"],
                    "summary": v["summary"],
                })
    if pkg_file:
        for pkg, ver in _parse_package_json(pkg_file["content"]):
            for v in _query_osv(pkg, ver, "npm"):
                findings.append({
                    "scanner": "dependencies",
                    "package": pkg,
                    "version": ver,
                    "cve_id": v["id"],
                    "severity": v["severity"],
                    "summary": v["summary"],
                })
    return findings
