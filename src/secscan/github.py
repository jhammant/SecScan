"""GitHub helpers: list user repos, clone to local workdir."""
from __future__ import annotations
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx


GITHUB_API = "https://api.github.com"


@dataclass
class RepoRef:
    owner: str
    name: str
    clone_url: str
    default_branch: str = "main"
    private: bool = False
    archived: bool = False
    fork: bool = False
    size_kb: int = 0

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


def parse_repo_url(url_or_slug: str) -> tuple[str, str]:
    """Accept 'owner/name', 'https://github.com/owner/name', or '...\\.git'."""
    s = url_or_slug.strip().removesuffix(".git")
    if "/" not in s:
        raise ValueError(f"Cannot parse repo spec: {url_or_slug!r}")
    if s.startswith("http"):
        parts = urlparse(s).path.strip("/").split("/")
    else:
        parts = s.split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse repo spec: {url_or_slug!r}")
    return parts[-2], parts[-1]


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "secscan/0.1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(base_url=GITHUB_API, headers=headers, timeout=30.0)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    def get_repo(self, owner: str, name: str) -> RepoRef:
        r = self._http.get(f"/repos/{owner}/{name}")
        r.raise_for_status()
        d = r.json()
        return _to_repo_ref(d)

    def list_user_repos(
        self, user: str, *, include_forks: bool = False, include_archived: bool = False
    ) -> list[RepoRef]:
        """List all repos for a user or org (public; private if token authorizes)."""
        repos: list[RepoRef] = []
        # Try /users first; if it 404s and token is present, fall back to /user/repos (auth'd user)
        page = 1
        while True:
            r = self._http.get(
                f"/users/{user}/repos",
                params={"per_page": 100, "page": page, "type": "owner", "sort": "updated"},
            )
            if r.status_code == 404:
                # Maybe it's an org
                r = self._http.get(
                    f"/orgs/{user}/repos",
                    params={"per_page": 100, "page": page, "type": "all", "sort": "updated"},
                )
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            for d in batch:
                ref = _to_repo_ref(d)
                if ref.fork and not include_forks:
                    continue
                if ref.archived and not include_archived:
                    continue
                repos.append(ref)
            if len(batch) < 100:
                break
            page += 1
        return repos

    def clone(self, repo: RepoRef, dest: Path, *, depth: int = 1) -> Path:
        """Shallow-clone into dest/<owner>/<name>. Returns the path."""
        target = dest / repo.owner / repo.name
        if target.exists():
            # Update instead of re-clone
            subprocess.run(
                ["git", "-C", str(target), "fetch", "--depth", str(depth), "origin", repo.default_branch],
                check=False, capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(target), "reset", "--hard", f"origin/{repo.default_branch}"],
                check=False, capture_output=True,
            )
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        url = _auth_clone_url(repo.clone_url, self.token)
        subprocess.run(
            ["git", "clone", "--depth", str(depth), url, str(target)],
            check=True, capture_output=True,
        )
        return target


def _to_repo_ref(d: dict) -> RepoRef:
    return RepoRef(
        owner=d["owner"]["login"],
        name=d["name"],
        clone_url=d["clone_url"],
        default_branch=d.get("default_branch") or "main",
        private=bool(d.get("private")),
        archived=bool(d.get("archived")),
        fork=bool(d.get("fork")),
        size_kb=int(d.get("size") or 0),
    )


def _auth_clone_url(clone_url: str, token: str | None) -> str:
    if not token:
        return clone_url
    # Inject token for private repos: https://<token>@github.com/owner/name.git
    return re.sub(r"^https://", f"https://{token}@", clone_url, count=1)


def current_commit(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        )
        return out.stdout.strip()
    except subprocess.CalledProcessError:
        return None
