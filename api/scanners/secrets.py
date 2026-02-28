import re


SECRET_PATTERNS = [
    ("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[a-zA-Z0-9]{24,}")),
    ("Stripe Publishable Key", re.compile(r"pk_live_[a-zA-Z0-9]{24,}")),
    ("GitHub Token", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
]
GENERIC = re.compile(
    r"(password|secret|api_key)\s*=\s*['\"]?([^'\"\s]{9,})['\"]?",
    re.IGNORECASE,
)
PLACEHOLDERS = {"your_key_here", "xxx", "changeme", "example", "placeholder", "secret", "password"}


def _is_placeholder(val: str) -> bool:
    v = val.lower().strip()
    if len(v) < 9:
        return True
    return v in PLACEHOLDERS or v.startswith("your_") or v.startswith("<") or v.endswith(">")


def scan(files: list[dict]) -> list[dict]:
    findings = []
    for f in files:
        path = f.get("path", "")
        content = f.get("content", "")
        for i, line in enumerate(content.splitlines(), 1):
            for name, pat in SECRET_PATTERNS:
                for m in pat.finditer(line):
                    findings.append({
                        "scanner": "secrets",
                        "path": path,
                        "line_no": i,
                        "line_content": line.strip(),
                        "pattern_name": name,
                        "evidence": m.group(0)[:50] + ("..." if len(m.group(0)) > 50 else ""),
                    })
            for m in GENERIC.finditer(line):
                val = m.group(2)
                if not _is_placeholder(val):
                    findings.append({
                        "scanner": "secrets",
                        "path": path,
                        "line_no": i,
                        "line_content": line.strip(),
                        "pattern_name": "Generic secret",
                        "evidence": m.group(0)[:60] + ("..." if len(m.group(0)) > 60 else ""),
                    })
    return findings
