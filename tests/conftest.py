from __future__ import annotations

import httpx
import pytest
import respx


@pytest.fixture
def respx_mock():
    # Override the plugin fixture: don't require every registered route to be hit,
    # but still fail if the broker makes an un-mocked external call.
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as mock:
        yield mock

REAL_LOOKING_TOKEN = "ghp_" + "A" * 36  # planted in mocked GitHub payloads
BROKER_TOKEN = "test-broker-token-0000000000"
# Deliberately NOT a recognised token shape: exercises literal-match redaction
# (redact_literals) rather than pattern masking.
DOTENV_SECRET = "brokertest-unconventional-secret-" + "z" * 20


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env(tmp_path, monkeypatch):
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"GITHUB_TOKEN={DOTENV_SECRET}\n")
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("BROKER_API_TOKEN", BROKER_TOKEN)
    monkeypatch.setenv("CONFIG_PATH", "config/credentials.yaml")
    monkeypatch.setenv("DOTENV_PATH", str(dotenv))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit))
    return {"dotenv": dotenv, "audit": audit}


@pytest.fixture
def app(env, fake_clock):
    from app.main import create_app

    return create_app(clock=fake_clock)


@pytest.fixture
async def client(app):
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://broker.test"
        ) as c:
            c.headers["Authorization"] = f"Bearer {BROKER_TOKEN}"
            yield c


@pytest.fixture
def gh(respx_mock):
    """Mock api.github.com with payloads that intentionally embed secrets."""
    base = "https://api.github.com"
    respx_mock.get(f"{base}/user/repos").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "name": "demo",
                    "full_name": "example-org/demo",
                    "private": True,
                    "html_url": "https://github.com/example-org/demo",
                    "description": f"token leak {REAL_LOOKING_TOKEN} here",
                    "default_branch": "main",
                    "owner": {"login": "example-org", "id": 99, "email": "x@y.z"},
                    "permissions": {"admin": True},
                },
                {
                    "id": 2,
                    "name": "oops",
                    "full_name": "example-org/oops",
                    "private": True,
                    "html_url": "https://github.com/example-org/oops",
                    # the broker's OWN github token pasted verbatim into a description
                    "description": f"pasted our creds: {DOTENV_SECRET} whoops",
                    "default_branch": "main",
                },
            ],
        )
    )
    respx_mock.get(f"{base}/repos/example-org/demo").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 1,
                "name": "demo",
                "full_name": "example-org/demo",
                "private": True,
                "html_url": "https://github.com/example-org/demo",
                "description": "clean",
                "default_branch": "main",
                "license": {"spdx_id": "MIT", "key": "mit"},
                "secret_scanning": {"status": "enabled"},
            },
        )
    )
    respx_mock.get(f"{base}/repos/example-org/demo/issues").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "number": 7,
                    "title": "bug",
                    "state": "open",
                    "html_url": "https://github.com/example-org/demo/issues/7",
                    "user": {"login": "someone", "id": 5},
                    "labels": [{"name": "bug", "id": 1}],
                    "comments": 2,
                    "body": f"here is my key {REAL_LOOKING_TOKEN}",
                }
            ],
        )
    )
    respx_mock.get(f"{base}/repos/example-org/demo/issues/7").mock(
        return_value=httpx.Response(
            200,
            json={
                "number": 7,
                "title": "bug",
                "state": "open",
                "html_url": "https://github.com/example-org/demo/issues/7",
                "user": {"login": "someone"},
                "labels": [],
                "comments": 0,
                "body": f"secret {REAL_LOOKING_TOKEN} in body " * 5,
            },
        )
    )
    return respx_mock


async def issue_handle(client, credential_id="github_reader") -> str:
    r = await client.post("/credentials/request", json={"credential_id": credential_id})
    assert r.status_code == 200, r.text
    return r.json()["handle"]
