import base64
import httpx

GITHUB_API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github.v3+json"}


def exchange_code_for_token(code: str, client_id: str, client_secret: str) -> str:
    r = httpx.post(
        "https://github.com/login/oauth/access_token",
        json={"client_id": client_id, "client_secret": client_secret, "code": code},
        headers={"Accept": "application/json"},
        timeout=15.0,
    )
    r.raise_for_status()
    token = r.json().get("access_token", "")
    if not token:
        raise ValueError("GitHub OAuth failed: " + r.json().get("error_description", "no token returned"))
    return token


def list_user_repos(token: str) -> list[str]:
    repos = []
    with httpx.Client(timeout=15.0) as client:
        page = 1
        while len(repos) < 200:
            r = client.get(
                f"{GITHUB_API}/user/repos",
                headers={**HEADERS, "Authorization": f"token {token}"},
                params={"sort": "updated", "per_page": 100, "page": page},
            )
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            for repo in batch:
                if repo.get("permissions", {}).get("push"):
                    repos.append(repo["full_name"])
            if len(batch) < 100:
                break
            page += 1
    return repos


def _parse_repo(repo_full_name: str) -> tuple[str, str]:
    parts = repo_full_name.split("/", 1)
    if len(parts) != 2:
        raise ValueError("repo_full_name must be owner/repo")
    return parts[0], parts[1]


def _skip_path(path: str) -> bool:
    p = path.lower()
    return "node_modules" in p or p.startswith(".git/") or p == ".git"


def fetch_repo_files(repo_full_name: str, token: str) -> list[dict]:
    owner, repo = _parse_repo(repo_full_name)
    headers = {**HEADERS, "Authorization": f"token {token}"}
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers)
        r.raise_for_status()
        default_branch = r.json()["default_branch"]
        ref = client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{default_branch}",
            headers=headers,
        )
        ref.raise_for_status()
        tree_sha = ref.json()["object"]["sha"]
        tree_r = client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{tree_sha}",
            params={"recursive": "1"},
            headers=headers,
        )
        tree_r.raise_for_status()
        tree = tree_r.json().get("tree", [])
    blobs = [t for t in tree if t.get("type") == "blob" and not _skip_path(t.get("path", "")) and t.get("size", 0) < 100000][:50]
    out = []
    with httpx.Client(timeout=60.0) as client:
        for b in blobs:
            path = b.get("path", "")
            r = client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/git/blobs/{b['sha']}",
                headers={**HEADERS, "Authorization": f"token {token}"},
            )
            r.raise_for_status()
            raw = r.json().get("content", "")
            try:
                content = base64.b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                continue
            if "\x00" in content:
                continue
            out.append({"path": path, "content": content})
    return out


def commit_file(repo_full_name: str, token: str, filename: str, content: str) -> None:
    owner, repo = _parse_repo(repo_full_name)
    headers = {**HEADERS, "Authorization": f"token {token}"}
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers)
        r.raise_for_status()
        default_branch = r.json()["default_branch"]
        ref_r = client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{default_branch}",
            headers=headers,
        )
        ref_r.raise_for_status()
        commit_sha = ref_r.json()["object"]["sha"]
        commit_r = client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/commits/{commit_sha}",
            headers=headers,
        )
        commit_r.raise_for_status()
        base_tree_sha = commit_r.json()["tree"]["sha"]
        blob_r = client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/blobs",
            headers=headers,
            json={"content": base64.b64encode(content.encode("utf-8")).decode("ascii"), "encoding": "base64"},
        )
        blob_r.raise_for_status()
        blob_sha = blob_r.json()["sha"]
        tree_r = client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{base_tree_sha}",
            headers=headers,
        )
        tree_r.raise_for_status()
        entries = [e for e in tree_r.json().get("tree", []) if e.get("path") != filename]
        entries.append({"path": filename, "mode": "100644", "type": "blob", "sha": blob_sha})
        new_tree_r = client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees",
            headers=headers,
            json={"base_tree": base_tree_sha, "tree": entries},
        )
        new_tree_r.raise_for_status()
        new_tree_sha = new_tree_r.json()["sha"]
        new_commit_r = client.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/commits",
            headers=headers,
            json={
                "message": "VibeSec: security report",
                "tree": new_tree_sha,
                "parents": [commit_sha],
            },
        )
        new_commit_r.raise_for_status()
        new_commit_sha = new_commit_r.json()["sha"]
        client.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/refs/heads/{default_branch}",
            headers=headers,
            json={"sha": new_commit_sha},
        ).raise_for_status()
