"""GitHub read-only connector (v0.1).

Base URL is fixed (no SSRF surface). Redirects are not followed. Responses are
allowlist-extracted and pattern-masked before leaving the broker; upstream
headers are never forwarded.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.actions.base import ActionExecutor, ActionResult, ActionSpec
from app.errors import ProviderError
from app.security.sanitizer import mask_secrets

GITHUB_BASE_URL = "https://api.github.com"

# Hard ceiling on an upstream response body, independent of the per-action
# post-sanitise caps in BrokerConfig. Bounds decode/sanitise work on a
# pathological or compressed response. True streaming enforcement is a v0.2 item.
_MAX_UPSTREAM_BYTES = 8 * 1024 * 1024

_OWNER = Annotated[str, Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")]
_REPO = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")]
_PER_PAGE = Annotated[int, Field(ge=1, le=100)]
_PAGE = Annotated[int, Field(ge=1)]


# --------------------------------------------------------------------------- #
# Parameter models (path + query together; extra keys forbidden)              #
# --------------------------------------------------------------------------- #
class ListRepositoriesParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    visibility: Literal["all", "public", "private"] = "all"
    affiliation: Literal["owner", "collaborator", "organization_member"] = "owner"
    sort: Literal["created", "updated", "pushed", "full_name"] = "full_name"
    per_page: _PER_PAGE = 30
    page: _PAGE = 1


class GetRepositoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: _OWNER
    repo: _REPO


class ListIssuesParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: _OWNER
    repo: _REPO
    state: Literal["open", "closed", "all"] = "open"
    labels: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ,_\-]{0,200}$")] = ""
    sort: Literal["created", "updated", "comments"] = "created"
    direction: Literal["asc", "desc"] = "desc"
    per_page: _PER_PAGE = 30
    page: _PAGE = 1


class GetIssueParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: _OWNER
    repo: _REPO
    number: Annotated[int, Field(ge=1)]


# --------------------------------------------------------------------------- #
# Sanitisers (allowlist extraction). Unknown fields are dropped.              #
# --------------------------------------------------------------------------- #
def _repo_summary(r: dict) -> dict:
    return {
        "id": r.get("id"),
        "name": r.get("name"),
        "full_name": r.get("full_name"),
        "private": r.get("private"),
        "html_url": r.get("html_url"),
        "description": mask_secrets(r.get("description") or ""),
        "fork": r.get("fork"),
        "default_branch": r.get("default_branch"),
        "language": r.get("language"),
        "archived": r.get("archived"),
        "visibility": r.get("visibility"),
        "updated_at": r.get("updated_at"),
        "pushed_at": r.get("pushed_at"),
    }


def _repo_detail(r: dict) -> dict:
    out = _repo_summary(r)
    lic = r.get("license") or {}
    out.update(
        {
            "topics": r.get("topics") or [],
            "license": (lic or {}).get("spdx_id"),
            "stargazers_count": r.get("stargazers_count"),
            "forks_count": r.get("forks_count"),
            "open_issues_count": r.get("open_issues_count"),
            "created_at": r.get("created_at"),
        }
    )
    return out


def _issue_summary(i: dict) -> dict:
    return {
        "number": i.get("number"),
        "title": mask_secrets(i.get("title") or ""),
        "state": i.get("state"),
        "html_url": i.get("html_url"),
        "user": (i.get("user") or {}).get("login"),
        "labels": [lbl.get("name") for lbl in (i.get("labels") or []) if isinstance(lbl, dict)],
        "comments": i.get("comments"),
        "created_at": i.get("created_at"),
        "updated_at": i.get("updated_at"),
        "closed_at": i.get("closed_at"),
        "draft": i.get("draft"),
        "is_pull_request": "pull_request" in i,
    }


def _issue_detail(i: dict) -> dict:
    out = _issue_summary(i)
    body = i.get("body") or ""
    # Mask first, then truncate, so a token straddling the cut is never half-returned.
    out["body_preview"] = mask_secrets(body)[:2000]
    return out


def _sanitize_list(fn):
    def _inner(body: Any) -> list:
        if not isinstance(body, list):
            raise ProviderError()
        return [fn(x) for x in body if isinstance(x, dict)]

    return _inner


def _sanitize_obj(fn):
    def _inner(body: Any) -> dict:
        if not isinstance(body, dict):
            raise ProviderError()
        return fn(body)

    return _inner


# --------------------------------------------------------------------------- #
SPECS: dict[str, ActionSpec] = {
    "list_repositories": ActionSpec(
        name="list_repositories",
        method="GET",
        path_template="/user/repos",
        param_model=ListRepositoriesParams,
        path_fields=frozenset(),
        query_fields=frozenset({"visibility", "affiliation", "sort", "per_page", "page"}),
        sanitize=_sanitize_list(_repo_summary),
    ),
    "get_repository": ActionSpec(
        name="get_repository",
        method="GET",
        path_template="/repos/{owner}/{repo}",
        param_model=GetRepositoryParams,
        path_fields=frozenset({"owner", "repo"}),
        query_fields=frozenset(),
        sanitize=_sanitize_obj(_repo_detail),
    ),
    "list_issues": ActionSpec(
        name="list_issues",
        method="GET",
        path_template="/repos/{owner}/{repo}/issues",
        param_model=ListIssuesParams,
        path_fields=frozenset({"owner", "repo"}),
        query_fields=frozenset({"state", "labels", "sort", "direction", "per_page", "page"}),
        sanitize=_sanitize_list(_issue_summary),
    ),
    "get_issue": ActionSpec(
        name="get_issue",
        method="GET",
        path_template="/repos/{owner}/{repo}/issues/{number}",
        param_model=GetIssueParams,
        path_fields=frozenset({"owner", "repo", "number"}),
        query_fields=frozenset(),
        sanitize=_sanitize_obj(_issue_detail),
    ),
}


class GitHubReadExecutor(ActionExecutor):
    connector = "github"
    specs = SPECS

    def __init__(self, http: httpx.AsyncClient, base_url: str = GITHUB_BASE_URL) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")

    async def run(self, spec: ActionSpec, params: BaseModel, *, secret: str) -> ActionResult:
        values = params.model_dump()
        path = spec.path_template
        for field in spec.path_fields:
            path = path.replace("{" + field + "}", str(values[field]))
        # Defence in depth: no traversal segments survived templating.
        if ".." in path or "//" in path[1:]:
            raise ProviderError()

        query = {
            k: values[k]
            for k in spec.query_fields
            if values.get(k) not in (None, "")
        }

        url = f"{self._base_url}{path}"
        headers = {
            "Authorization": f"Bearer {secret}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "credential-broker/0.1",
        }

        started = time.perf_counter()
        try:
            resp = await self._http.request(
                spec.method,
                url,
                params=query,
                headers=headers,
                follow_redirects=False,
                timeout=httpx.Timeout(15.0, connect=5.0),
            )
        except httpx.HTTPError:
            raise ProviderError() from None
        finally:
            del headers
        duration_ms = int((time.perf_counter() - started) * 1000)

        if resp.status_code >= 400:
            # Do not leak upstream body / headers.
            raise ProviderError()

        clen = resp.headers.get("content-length")
        if clen is not None and clen.isdigit() and int(clen) > _MAX_UPSTREAM_BYTES:
            raise ProviderError()
        if len(resp.content) > _MAX_UPSTREAM_BYTES:
            raise ProviderError()

        try:
            body = resp.json()
        except ValueError:
            raise ProviderError() from None

        return ActionResult(upstream_status=resp.status_code, body=body, duration_ms=duration_ms)
