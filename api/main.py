from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api import github_client
from api import report
from api import prioritize
from api.scanners import secrets, env_exposure, dependencies

app = FastAPI(title="VibeSec")


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
