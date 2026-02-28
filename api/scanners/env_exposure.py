import re

PLACEHOLDERS = {
    "your_key_here", "xxx", "changeme", "example", "placeholder",
    "secret", "password", "replace_me", "your_value", "env_value",
}
MAX_PLACEHOLDER_LEN = 20


def _env_ignored(gitignore_content: str) -> bool:
    for line in gitignore_content.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line:
            continue
        if line == ".env" or line.startswith(".env"):
            return True
    return False


def _parse_env_values(content: str) -> list[tuple[str, str]]:
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip().strip("'\"").strip()
        out.append((key, val))
    return out


def _looks_real(val: str) -> bool:
    if len(val) <= 8:
        return False
    if val.lower() in PLACEHOLDERS:
        return False
    if len(val) <= MAX_PLACEHOLDER_LEN and (val.startswith("your_") or val.startswith("<")):
        return False
    return True


def scan(files: list[dict]) -> list[dict]:
    findings = []
    gitignore = next((f for f in files if f.get("path") == ".gitignore"), None)
    gitignore_ok = _env_ignored(gitignore["content"]) if gitignore else False
    env_file = next((f for f in files if f.get("path") == ".env"), None)
    env_example = next((f for f in files if ".env.example" in f.get("path", "")), None)
    if env_file and not gitignore_ok:
        findings.append({
            "scanner": "env",
            "path": ".env",
            "issue": "dotenv_not_gitignored",
            "detail": ".env is committed and not listed in .gitignore",
        })
    if env_file:
        for key, val in _parse_env_values(env_file["content"]):
            if _looks_real(val):
                findings.append({
                    "scanner": "env",
                    "path": ".env",
                    "issue": "dotenv_has_real_values",
                    "detail": f"Key {key} has a non-placeholder value",
                })
                break
    if env_example:
        for key, val in _parse_env_values(env_example["content"]):
            if _looks_real(val):
                findings.append({
                    "scanner": "env",
                    "path": env_example.get("path", ".env.example"),
                    "issue": "dotenv_example_has_credentials",
                    "detail": f".env.example contains real-looking value for {key}",
                })
                break
    return findings
