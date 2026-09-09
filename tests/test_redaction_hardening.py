"""Post-review hardening (Codex 2026-09-09 FAIL findings)."""

from __future__ import annotations

import logging

from app.security.redaction import SecretRegistry, install
from app.security.sanitizer import redact_literals
from tests.conftest import DOTENV_SECRET, issue_handle


async def test_unconventional_secret_in_response_is_redacted(client, gh):
    """must-fix #1: a verbatim secret of unknown shape must not pass through."""
    handle = await issue_handle(client)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 200
    assert DOTENV_SECRET not in r.text
    repo2 = next(x for x in r.json()["data"] if x["name"] == "oops")
    assert "***REDACTED***" in repo2["description"]


def test_redact_literals_walks_nested_structures():
    data = {"a": ["x SEKRET_TOKEN_1234567 y", {"b": "SEKRET_TOKEN_1234567"}], "n": 5}
    out = redact_literals(data, ["SEKRET_TOKEN_1234567"])
    assert "SEKRET_TOKEN_1234567" not in repr(out)
    assert out["n"] == 5


def test_redact_literals_ignores_short_values():
    assert redact_literals("abc", ["abc"]) == "abc"  # < 8 chars: skip


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_logrecord_factory_redacts_unlisted_child_logger():
    """must-fix #2: redaction must not depend on which logger emits."""
    reg = SecretRegistry()
    reg.register(DOTENV_SECRET)
    install(reg)

    cap = _ListHandler()
    weird = logging.getLogger("some.third.party.lib.nobody.listed")
    weird.propagate = False
    weird.addHandler(cap)
    weird.setLevel(logging.INFO)
    try:
        weird.error("boom while using %s in a header", DOTENV_SECRET)
    finally:
        weird.removeHandler(cap)

    joined = "\n".join(cap.messages)
    assert DOTENV_SECRET not in joined
    assert "***REDACTED***" in joined


def test_install_does_not_stack_factories():
    for _ in range(5):
        install(SecretRegistry())
    reg = SecretRegistry()
    reg.register("STACKING_CHECK_SECRET_X")
    install(reg)

    cap = _ListHandler()
    lg = logging.getLogger("x.y.z")
    lg.propagate = False
    lg.addHandler(cap)
    lg.setLevel(logging.INFO)
    try:
        lg.warning("val=STACKING_CHECK_SECRET_X")
    finally:
        lg.removeHandler(cap)
    assert "STACKING_CHECK_SECRET_X" not in "\n".join(cap.messages)


async def test_expired_get_deregisters_secret(app, client, gh, fake_clock):
    """minor: store.get() auto-eviction must release the SecretRegistry ref."""
    handle = await issue_handle(client)
    reg = app.state.broker._secret_registry  # type: ignore[attr-defined]
    assert DOTENV_SECRET in reg.snapshot()

    fake_clock.advance(400)
    r = await client.post(
        "/execute", json={"credential_handle": handle, "action": "list_repositories"}
    )
    assert r.status_code == 410
    assert DOTENV_SECRET not in reg.snapshot()


async def test_shared_secret_multi_handle_refcount(app, client, fake_clock):
    h1 = await issue_handle(client)
    h2 = await issue_handle(client)
    reg = app.state.broker._secret_registry  # type: ignore[attr-defined]
    assert DOTENV_SECRET in reg.snapshot()

    await client.post("/credentials/revoke", json={"credential_handle": h1})
    assert DOTENV_SECRET in reg.snapshot()  # h2 still holds it

    await client.post("/credentials/revoke", json={"credential_handle": h2})
    assert DOTENV_SECRET not in reg.snapshot()


# --- Codex Round 3 nice-to-haves ---
async def test_rate_limit_before_unknown_credential_lookup(app, client):
    """Unknown credential_id floods must not bypass the request rate limiter."""
    # request_per_min default 20 → the 21st is rate-limited even for unknown ids
    codes = []
    for _ in range(25):
        r = await client.post("/credentials/request", json={"credential_id": "nope_unknown"})
        codes.append(r.status_code)
    assert 429 in codes
    assert codes.count(404) <= 20


def test_audit_sink_file_is_0600(tmp_path):
    from app.security.audit import AuditLogger

    sink = tmp_path / "sub" / "audit.jsonl"
    AuditLogger(sink_path=sink)
    AuditLogger(sink_path=sink)  # attach path
    # emit through a fresh logger bound to the same sink
    import logging

    lg = logging.getLogger("audit")
    lg.info('{"x":1}')
    for h in lg.handlers:
        h.flush()

    assert oct(sink.stat().st_mode & 0o777) == "0o600"
    assert oct(sink.parent.stat().st_mode & 0o777) == "0o700"
