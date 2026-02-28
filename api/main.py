import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel

from api import github_client
from api import report
from api import prioritize
from api.scanners import secrets, env_exposure, dependencies

app = FastAPI(title="VibeSec")

_DIR = os.path.dirname(__file__)

WORKFLOW_YML = """\
name: VibeSec Security Scan

on:
  push:
    branches: ["*"]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: Run VibeSec Scan
        run: |
          curl --max-time 55 -X POST https://web-production-210eb.up.railway.app/scan \\
            -H "Content-Type: application/json" \\
            -d '{"repo_full_name": "${{ github.repository }}", "github_token": "${{ secrets.GITHUB_TOKEN }}"}'
"""

_DARK = """
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d1117; color: #e6edf3;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 2.5rem; max-width: 520px; width: 90%; text-align: center;
  }
  h1 { font-size: 2rem; font-weight: 800; letter-spacing: -1px; margin-bottom: 0.4rem; }
  h1 span { color: #3fb950; }
  p { color: #8b949e; margin-bottom: 1.5rem; line-height: 1.6; }
  select {
    width: 100%; padding: 0.75rem 1rem; background: #0d1117; color: #e6edf3;
    border: 1px solid #30363d; border-radius: 8px; font-size: 0.95rem;
    margin-bottom: 1rem; appearance: none; cursor: pointer;
  }
  select:focus { outline: none; border-color: #58a6ff; }
  .btn {
    display: inline-block; width: 100%; padding: 0.85rem;
    background: #238636; color: #fff; border: none; border-radius: 8px;
    font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.15s;
  }
  .btn:hover { background: #2ea043; }
  .btn:disabled { background: #21262d; color: #484f58; cursor: default; }
  #status { margin-top: 1rem; font-size: 0.9rem; min-height: 1.4rem; }
  .success { color: #3fb950; }
  .error { color: #f85149; }
  code {
    font-family: 'SF Mono', Consolas, monospace; font-size: 0.85em;
    background: #21262d; padding: 1px 5px; border-radius: 4px; color: #79c0ff;
  }
  a { color: #58a6ff; text-decoration: none; }
"""


def _picker_page(token: str, options_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSec — Install</title>
  <style>{_DARK}</style>
</head><body>
  <div class="card">
    <h1>🛡️ Vibe<span>Sec</span></h1>
    <p>Select a repository to protect. VibeSec will scan it on every push and commit a <code>SECURITY_REPORT.md</code> with fix instructions.</p>
    <select id="repo">{options_html}</select>
    <button class="btn" id="btn" onclick="install()">Install VibeSec</button>
    <div id="status"></div>
  </div>
  <script>
    const TOKEN = {repr(token)};
    async function install() {{
      const repo = document.getElementById('repo').value;
      const btn = document.getElementById('btn');
      const status = document.getElementById('status');
      btn.disabled = true;
      btn.textContent = 'Installing...';
      status.textContent = '';
      try {{
        const r = await fetch('/install', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{repo_full_name: repo, token: TOKEN}})
        }});
        const data = await r.json();
        if (r.ok) {{
          status.className = 'success';
          status.innerHTML = '&#10003; Installed on <strong>' + repo + '</strong>. Push any commit to trigger your first scan.';
          btn.textContent = 'Installed';
        }} else {{
          throw new Error(data.detail || 'Unknown error');
        }}
      }} catch(e) {{
        status.className = 'error';
        status.textContent = 'Error: ' + e.message;
        btn.disabled = false;
        btn.textContent = 'Try Again';
      }}
    }}
  </script>
</body></html>"""


def _error_page(message: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8">
  <title>VibeSec — Error</title>
  <style>{_DARK}</style>
</head><body>
  <div class="card">
    <h1>🛡️ Vibe<span>Sec</span></h1>
    <p class="error" style="color:#f85149">{message}</p>
    <a href="/">&#8592; Try again</a>
  </div>
</body></html>"""


@app.get("/", response_class=FileResponse)
def index():
    return FileResponse(os.path.join(_DIR, "install.html"))


@app.get("/auth/login")
def auth_login():
    client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    if not client_id:
        raise HTTPException(500, "GITHUB_CLIENT_ID not configured")
    url = f"https://github.com/login/oauth/authorize?client_id={client_id}&scope=repo"
    return RedirectResponse(url)


@app.get("/auth/callback", response_class=HTMLResponse)
def auth_callback(code: str = ""):
    client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")
    if not code:
        return HTMLResponse(_error_page("No OAuth code received from GitHub."), status_code=400)
    try:
        token = github_client.exchange_code_for_token(code, client_id, client_secret)
        repos = github_client.list_user_repos(token)
    except Exception as e:
        return HTMLResponse(_error_page(str(e)), status_code=400)
    if not repos:
        return HTMLResponse(_error_page("No repositories found with push access."), status_code=400)
    options = "\n".join(f'<option value="{r}">{r}</option>' for r in repos)
    return HTMLResponse(_picker_page(token, options))


class InstallRequest(BaseModel):
    repo_full_name: str
    token: str


@app.post("/install")
def install(req: InstallRequest):
    try:
        github_client.commit_file(
            req.repo_full_name,
            req.token,
            ".github/workflows/vibesec.yml",
            WORKFLOW_YML,
        )
    except Exception as e:
        raise HTTPException(502, f"Install failed: {e}")
    return {"status": "ok", "repo": req.repo_full_name}


class ScanRequest(BaseModel):
    repo_full_name: str
    github_token: str


@app.post("/scan")
def scan(request: ScanRequest):
    if not request.repo_full_name or "/" not in request.repo_full_name:
        raise HTTPException(400, "repo_full_name must be owner/repo")
    if not request.github_token:
        raise HTTPException(400, "github_token required")
    try:
        files = github_client.fetch_repo_files(request.repo_full_name, request.github_token)
    except Exception as e:
        err = str(e).lower()
        if "401" in err or "unauthorized" in err:
            raise HTTPException(401, "Invalid or expired GitHub token")
        if "404" in err or "not found" in err:
            raise HTTPException(404, "Repo not found or no access")
        raise HTTPException(400, str(e) or "Failed to fetch repo")
    raw = []
    raw.extend(secrets.scan(files))
    raw.extend(env_exposure.scan(files))
    raw.extend(dependencies.scan(files))
    prioritized = prioritize.run(raw)
    report_content = report.generate(prioritized, request.repo_full_name)
    try:
        github_client.commit_file(
            request.repo_full_name,
            request.github_token,
            "SECURITY_REPORT.md",
            report_content,
        )
    except Exception as e:
        raise HTTPException(502, f"Failed to commit report: {e}")
    return {"status": "ok", "report_committed": True}
