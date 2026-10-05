from __future__ import annotations

import logging

from app.security.redaction import RedactionFilter, SecretRegistry
from tests.conftest import DOTENV_SECRET, REAL_LOOKING_TOKEN, issue_handle


async def test_no_secret_in_captured_logs(client, gh, caplog):
    """TEST-008: full flow, nothing sensitive in any log record."""
    reg = SecretRegistry()
    reg.register(DOTENV_SECRET)
    flt = RedactionFilter(reg)
    caplog.handler.addFilter(flt)

    with caplog.at_level(logging.DEBUG):
        handle = await issue_handle(client)
        await client.post(
            "/execute",
            json={"credential_handle": handle, "action": "list_issues",
                  "parameters": {"owner": "example-org", "repo": "demo"}},
        )
        await client.post("/credentials/revoke", json={"credential_handle": handle})

    text = caplog.text
    assert DOTENV_SECRET not in text
    assert REAL_LOOKING_TOKEN not in text
    assert "Bearer ghp_" not in text
    assert "Authorization" not in text or "Bearer" not in text


def test_redaction_filter_masks_registered_and_patterned():
    reg = SecretRegistry()
    reg.register("REGISTERED_SECRET_XYZ")
    flt = RedactionFilter(reg)
    rec = logging.LogRecord(
        "x", logging.INFO, __file__, 1,
        "leak REGISTERED_SECRET_XYZ and ghp_%s tail",
        ("B" * 36,), None,
    )
    flt.filter(rec)
    out = rec.getMessage()
    assert "REGISTERED_SECRET_XYZ" not in out
    assert "ghp_" not in out
    assert "***REDACTED***" in out


def test_audit_logger_rejects_free_text_fields():
    import pytest

    from app.security.audit import AuditLogger

    with pytest.raises(ValueError):
        AuditLogger().emit("x", note="here is the token ghp_...")


def test_exception_text_is_redacted_by_filter_and_factory():
    from app.security import redaction

    reg = SecretRegistry()
    reg.register("REGISTERED_SECRET_XYZ")
    try:
        raise RuntimeError("upstream said REGISTERED_SECRET_XYZ and ghp_" + "C" * 36)
    except RuntimeError:
        import sys

        exc_info = sys.exc_info()

    # Filter path
    rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "boom", (), exc_info)
    RedactionFilter(reg).filter(rec)
    out = logging.Formatter().format(rec)
    assert "REGISTERED_SECRET_XYZ" not in out
    assert "ghp_" + "C" * 36 not in out
    assert "RuntimeError" in out

    # Process-wide factory path
    redaction.install(reg)
    try:
        rec = logging.getLogRecordFactory()("x", logging.ERROR, __file__, 1, "boom", (), exc_info)
        out = logging.Formatter().format(rec)
        assert "REGISTERED_SECRET_XYZ" not in out
        assert "ghp_" + "C" * 36 not in out
    finally:
        logging.setLogRecordFactory(redaction._ORIGINAL_FACTORY)
