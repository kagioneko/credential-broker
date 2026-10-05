"""Real GitHub API smoke test for the Credential Broker.

Reads GITHUB_TOKEN / BROKER_API_TOKEN from env (populated from Vault by the
wrapper). Hits api.github.com for real. Prints only structural facts and
leak-check booleans — never a secret value or a raw response body.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile

import httpx

GH_TOKEN = os.environ["SMOKE_GITHUB_TOKEN"]
BROKER_TOKEN = os.environ["SMOKE_BROKER_TOKEN"]


def _fs_type(path: str) -> str | None:
    """Filesystem type of the mount containing ``path`` (Linux /proc only)."""
    path = os.path.realpath(path)
    best_mnt, best_type = "", None
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as f:
            for line in f:
                left, _, right = line.partition(" - ")
                mnt = left.split()[4].replace("\\040", " ")
                fstype = right.split()[0]
                prefix = mnt.rstrip("/") + "/"
                if (path == mnt or path.startswith(prefix)) and len(mnt) >= len(best_mnt):
                    best_mnt, best_type = mnt, fstype
    except (OSError, IndexError):
        return None
    return best_type


def _private_tmp_base() -> str:
    """A writable tmpfs/ramfs dir, so the token never reaches persistent disk."""
    for base in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm"):
        if (
            base
            and os.path.isdir(base)
            and os.access(base, os.W_OK)
            and _fs_type(base) in ("tmpfs", "ramfs")
        ):
            return base
    raise SystemExit("smoke: no RAM-backed (tmpfs/ramfs) directory; refusing to write the token to disk")


async def main() -> int:
    base = _private_tmp_base()  # fail closed before any secret is written
    # TemporaryDirectory removes the token file on normal exit AND on exceptions.
    with tempfile.TemporaryDirectory(prefix="credential-broker-smoke.", dir=base) as tmp:
        dotenv = os.path.join(tmp, ".env")
        with open(os.open(dotenv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(f"GITHUB_TOKEN={GH_TOKEN}\n")
        return await _run(dotenv)


async def _run(dotenv: str) -> int:
    os.environ["BROKER_API_TOKEN"] = BROKER_TOKEN
    os.environ["CONFIG_PATH"] = "config/credentials.yaml"
    os.environ["DOTENV_PATH"] = dotenv

    from app.main import create_app

    app = create_app()
    ok = True

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://smoke") as c:
            c.headers["Authorization"] = f"Bearer {BROKER_TOKEN}"

            r = await c.get("/capabilities")
            print(f"[capabilities] {r.status_code} creds={[x['credential_id'] for x in r.json()['credentials']]}")

            r = await c.post("/credentials/request", json={"credential_id": "github_reader"})
            print(f"[request] {r.status_code} keys={sorted(r.json())}")
            ok &= r.status_code == 200 and GH_TOKEN not in r.text
            handle = r.json()["handle"]

            r = await c.post("/execute", json={"credential_handle": handle, "action": "list_repositories", "parameters": {"per_page": 5}})
            body = r.json()
            n = len(body["data"]) if isinstance(body.get("data"), list) else "?"
            print(f"[list_repositories] {r.status_code} status={body.get('status')} repos={n} token_leak={GH_TOKEN in r.text}")
            ok &= r.status_code == 200 and GH_TOKEN not in r.text

            first_full_name = None
            if isinstance(body.get("data"), list) and body["data"]:
                first_full_name = body["data"][0].get("full_name")
                keys = sorted(body["data"][0].keys())
                print(f"           sample repo fields={keys}")

            if first_full_name and "/" in first_full_name:
                owner, repo = first_full_name.split("/", 1)
                r = await c.post("/execute", json={"credential_handle": handle, "action": "get_repository", "parameters": {"owner": owner, "repo": repo}})
                print(f"[get_repository] {r.status_code} status={r.json().get('status')} token_leak={GH_TOKEN in r.text}")
                ok &= r.status_code == 200 and GH_TOKEN not in r.text

            r = await c.post("/execute", json={"credential_handle": handle, "action": "delete_repository", "parameters": {}})
            print(f"[delete_repository blocked?] {r.status_code} -> {r.json()}")
            ok &= r.status_code == 403

            r = await c.post("/credentials/revoke", json={"credential_handle": handle})
            print(f"[revoke] {r.status_code} -> {r.json()}")

            r = await c.post("/execute", json={"credential_handle": handle, "action": "list_repositories"})
            print(f"[execute after revoke] {r.status_code} -> {r.json()}")
            ok &= r.status_code == 410

    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
