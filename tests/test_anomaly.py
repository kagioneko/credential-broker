from __future__ import annotations

import json

from app.anomaly import AnomalyMonitor
from app.models.config import AnomalyConfig
from tests.conftest import FakeClock, issue_handle


def _mon(**over):
    cfg = AnomalyConfig(**{"window_sec": 60, "cooldown_sec": 300, **over})
    return AnomalyMonitor(cfg, clock=FakeClock())


def test_enumeration_counts_distinct_unknown_ids():
    m = _mon()
    out = []
    for cid in ["aws", "stripe", "openai", "gcp"]:
        out += m.observe("policy_denied", {"reason": "unknown", "credential_id": cid, "client_id": "a"})
    assert out == []  # 4 < threshold 5
    out = m.observe("policy_denied", {"reason": "unknown", "credential_id": "azure", "client_id": "a"})
    assert len(out) == 1
    assert out[0]["pattern"] == "credential_enumeration"
    assert out[0]["count"] == 5


def test_enumeration_ignores_repeats_of_same_id():
    m = _mon()
    out = []
    for _ in range(10):
        out += m.observe("policy_denied", {"reason": "unknown", "credential_id": "aws", "client_id": "a"})
    assert out == []  # only 1 distinct id


def test_denied_streak():
    m = _mon()
    fires = 0
    for _ in range(5):
        fires += len(m.observe("policy_denied", {"reason": "policy", "client_id": "x"}))
    assert fires == 1


def test_expired_replay():
    m = _mon()
    fires = 0
    for _ in range(5):
        fires += len(
            m.observe("action_executed", {"result": "denied", "reason": "ttl", "client_id": "x"})
        )
    assert fires == 1


def test_rate_limit_hits_threshold_is_3():
    m = _mon()
    fires = 0
    for _ in range(3):
        fires += len(m.observe("rate_limited", {"client_id": "x", "reason": "rate_limit"}))
    assert fires == 1


def test_cooldown_suppresses_repeat():
    clock = FakeClock()
    m = AnomalyMonitor(AnomalyConfig(window_sec=60, cooldown_sec=300), clock=clock)
    for _ in range(5):
        m.observe("policy_denied", {"reason": "policy", "client_id": "x"})
    # window slides but cooldown active
    clock.advance(120)
    fired = 0
    for _ in range(5):
        fired += len(m.observe("policy_denied", {"reason": "policy", "client_id": "x"}))
    assert fired == 0
    clock.advance(300)
    for _ in range(5):
        fired += len(m.observe("policy_denied", {"reason": "policy", "client_id": "x"}))
    assert fired == 1


def test_window_expiry():
    clock = FakeClock()
    m = AnomalyMonitor(AnomalyConfig(window_sec=60), clock=clock)
    for _ in range(4):
        m.observe("policy_denied", {"reason": "policy", "client_id": "x"})
    clock.advance(61)  # first 4 fall out of window
    fired = 0
    for _ in range(4):
        fired += len(m.observe("policy_denied", {"reason": "policy", "client_id": "x"}))
    assert fired == 0  # only 4 in the new window, threshold 5


def test_disabled_monitor_is_silent():
    m = AnomalyMonitor(AnomalyConfig(enabled=False), clock=FakeClock())
    out = []
    for _ in range(20):
        out += m.observe("rate_limited", {"client_id": "x"})
    assert out == []


# --- integration: anomaly lands in the audit sink file ---
async def test_enumeration_reaches_audit_sink(app, client, env):
    for cid in ["aws_secret", "stripe_key", "openai_key", "gcp_sa", "azure_kv"]:
        r = await client.post("/credentials/request", json={"credential_id": cid})
        assert r.status_code == 404

    lines = env["audit"].read_text().splitlines()
    events = [json.loads(x) for x in lines]
    anomalies = [e for e in events if e["event"] == "anomaly_suspected"]
    assert len(anomalies) == 1
    assert anomalies[0]["pattern"] == "credential_enumeration"
    assert anomalies[0]["count"] == 5
    # the sink must not contain the broker's own secret
    from tests.conftest import DOTENV_SECRET

    assert DOTENV_SECRET not in env["audit"].read_text()


async def test_normal_use_produces_no_anomaly(app, client, gh, env):
    h = await issue_handle(client)
    await client.post("/execute", json={"credential_handle": h, "action": "list_repositories"})
    await client.post("/credentials/revoke", json={"credential_handle": h})
    events = [json.loads(x) for x in env["audit"].read_text().splitlines()]
    assert not [e for e in events if e["event"] == "anomaly_suspected"]
