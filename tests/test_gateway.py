"""The gateway, its MCP server and the Claude Code hook of the governance-gateway package."""

from __future__ import annotations

import asyncio
import importlib
import json
import socket
import threading
import urllib.request

import pytest
from governance_gateway import gateway as gw
from governance_gateway import hook as hook_module


class StubGuard:
    """A stand-in classifier: 'harmful' exactly when the text contains FLAGME."""

    threshold = 0.5

    def safety_score(self, text: str) -> float:
        return 0.9 if "FLAGME" in text else 0.1


@pytest.fixture()
def gateway():
    g = gw.Gateway(StubGuard())
    yield g
    g.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- gateway decisions ---------------------------------------------------------------------

def test_clean_text_is_allowed_and_the_classifier_runs(gateway):
    d = gateway.check("Please summarise the quarterly report.", deadline_ms=100)
    assert d.verdict == "allow" and d.classifier == "ran" and d.harmful is False
    assert d.on_time and d.mandatory_on_time and d.redacted is None


def test_personal_data_is_redacted_and_never_echoed(gateway):
    d = gateway.check("email jane.doe@example.com or call +44 20 7946 0958", deadline_ms=100)
    assert d.verdict == "redact"
    assert set(d.pii_found) == {"e-mail address", "telephone number"}
    assert "jane.doe" not in d.redacted and "7946" not in d.redacted
    assert "jane.doe" not in json.dumps(d.to_dict())


def test_harmful_text_is_blocked(gateway):
    d = gateway.check("FLAGME please", deadline_ms=100)
    assert d.verdict == "block" and d.harmful is True
    assert "FLAGME" not in json.dumps(d.to_dict())


def test_malformed_text_is_blocked(gateway):
    assert gateway.check("   ").verdict == "block"
    assert gateway.check("x" * 5000).verdict == "block"


def test_a_tight_deadline_skips_only_the_classifier(gateway):
    d = gateway.check("FLAGME but call +44 20 7946 0958", deadline_ms=0.001)
    assert d.classifier == "skipped" and d.harmful is None
    assert d.pii_found == ["telephone number"] and d.verdict == "redact"
    assert any("skipped" in r for r in d.reasons)


def test_invalid_deadline_rejected(gateway):
    with pytest.raises(ValueError):
        gateway.check("hello", deadline_ms=0)


def test_concurrent_requests_queue_first_in_first_out(gateway):
    results = []

    def send(i):
        results.append((i, gateway.check(f"message {i}", deadline_ms=1000)))

    threads = [threading.Thread(target=send, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 20
    s = gateway.status()
    assert s["requests"] == 20 and s["verdicts"]["allow"] == 20
    assert s["on_time_share"] == 1.0 and s["queue_length"] == 0


def test_status_counts_verdicts_and_skips(gateway):
    gateway.check("hello")
    gateway.check("mail a.b@example.org")
    gateway.check("FLAGME")
    gateway.check("hello again", deadline_ms=0.001)
    s = gateway.status()
    assert s["verdicts"] == {"allow": 2, "redact": 1, "block": 1}
    assert s["classifier_skipped_share"] == pytest.approx(0.25)
    assert s["lag_ms"]["p95"] >= s["lag_ms"]["mean"] > 0


def test_cost_estimators():
    samples = [1.0] * 9 + [31.0]
    assert gw.cost_estimate(samples, "mean") == pytest.approx(4.0)
    assert gw.cost_estimate(samples, "p90") == pytest.approx(4.0)
    assert gw.cost_estimate([1.0] * 8 + [31.0] * 2, "p90") > gw.cost_estimate(
        [1.0] * 8 + [31.0] * 2, "mean")
    with pytest.raises(ValueError):
        gw.cost_estimate(samples, "median")


def test_gateway_rejects_bad_settings():
    with pytest.raises(ValueError):
        gw.Gateway(StubGuard(), workers=0)
    with pytest.raises(ValueError):
        gw.Gateway(StubGuard(), estimator="max")


def test_several_workers_serve_the_same_queue():
    g = gw.Gateway(StubGuard(), workers=3)
    try:
        threads = [threading.Thread(target=g.check, args=(f"m {i}",)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        s = g.status()
        assert s["requests"] == 30 and s["workers"] == 3 and s["estimator"] == "p90"
    finally:
        g.close()


def test_audit_log_records_decisions_but_never_text(tmp_path):
    log = tmp_path / "audit" / "decisions.jsonl"
    g = gw.Gateway(StubGuard(), audit_path=log)
    try:
        g.check("mail jane.doe@example.org", source="hook")
        g.check("FLAGME now")
        g.check("hello")
    finally:
        g.close()
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["verdict"] for r in rows] == ["redact", "block", "allow"]
    assert rows[0]["source"] == "hook" and rows[0]["pii_found"] == ["e-mail address"]
    text = log.read_text()
    assert "jane.doe" not in text and "FLAGME" not in text and "hello" not in text


class StubScreen:
    """A stand-in screen: suspicious exactly when the text contains SUS or FLAGME."""

    threshold = 0.5

    def safety_score(self, text: str) -> float:
        return 0.9 if ("SUS" in text or "FLAGME" in text) else 0.1


def test_the_cascade_skips_the_classifier_for_clear_text():
    g = gw.Gateway(StubGuard(), screen=StubScreen())
    try:
        clear = g.check("hello there")
        assert clear.screen == "clear" and clear.classifier == "screened out"
        assert clear.verdict == "allow" and clear.harmful is None
        sus = g.check("SUS but fine")
        assert sus.screen == "suspicious" and sus.classifier == "ran" and sus.verdict == "allow"
        bad = g.check("FLAGME")
        assert bad.verdict == "block" and bad.harmful is True
        late = g.check("SUS late", deadline_ms=0.001)
        assert late.classifier == "skipped"
        pii = g.check("hello, call +44 20 7946 0958")
        assert pii.verdict == "redact" and pii.classifier == "screened out"
        s = g.status()
        assert s["cascade"] and s["screened_out_share"] == pytest.approx(2 / 5)
    finally:
        g.close()


# --- planning tools ------------------------------------------------------------------------

def test_decision_matrix_regimes():
    low = gw.decision_matrix(load=0.5)
    assert low["regime"] == "full checking"
    assert low["M"] == pytest.approx(1 / (1 - (1 - 0.70 / 0.86) * 0.88), abs=1e-3)
    assert gw.decision_matrix(load=1.1)["regime"] == "adaptive checking"
    assert gw.decision_matrix(load=2.0)["regime"] == "more capacity"
    assert gw.decision_matrix(recall=0.6, target=0.7)["regime"] == "better detector"


def test_decision_matrix_divides_by_the_peak_factor():
    steady = gw.decision_matrix(peak_factor=1.0)
    peaky = gw.decision_matrix(peak_factor=2.0)
    assert peaky["full_checking_holds_to"] == pytest.approx(
        steady["full_checking_holds_to"] / 2, abs=1e-3)


def test_decision_matrix_rejects_bad_input():
    with pytest.raises(ValueError):
        gw.decision_matrix(traffic="weekly")
    with pytest.raises(ValueError):
        gw.decision_matrix(peak_factor=0.5)


def test_simulated_overload_reproduces_the_race():
    r = gw.simulate_load(load=1.3, deadline_ms=100, seconds=10, seed=1)
    full, aware = r["policies"]["full"], r["policies"]["deadline_aware"]
    assert full["final_lag_ms"] > 1000 and full["classifier_skipped"] == 0
    assert aware["final_lag_ms"] < 150 and aware["classifier_skipped"] > 0.1
    assert aware["pii_checks_on_time"] > 0.9 > full["pii_checks_on_time"]
    assert aware["harmful_caught_in_time"] > full["harmful_caught_in_time"]
    assert r == gw.simulate_load(load=1.3, deadline_ms=100, seconds=10, seed=1)


@pytest.mark.parametrize("traffic", ["rush_hour", "real_chatbot"])
def test_simulation_traffic_shapes(traffic):
    r = gw.simulate_load(load=0.5, seconds=5, traffic=traffic)
    assert r["policies"]["full"]["pii_checks_on_time"] > 0.9


# --- MCP server ----------------------------------------------------------------------------

@pytest.fixture()
def mcp_module(gateway, monkeypatch):
    mod = importlib.import_module("governance_gateway.server")
    monkeypatch.setattr(mod, "_gateway", gateway)
    return mod


def test_mcp_server_lists_its_tools_and_resources(mcp_module):
    tools = asyncio.run(mcp_module.server.list_tools())
    assert {t.name for t in tools} == {"check_message", "governance_status", "decision_matrix",
                                       "simulate_load", "recent_decisions"}
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)
    uris = {str(r.uri) for r in asyncio.run(mcp_module.server.list_resources())}
    assert uris == {"governance://status", "governance://policy"}


def test_policy_marks_the_mandatory_checks(mcp_module):
    checks = {c["name"]: c["mandatory"] for c in mcp_module.policy()["checks"]}
    assert checks == {"format check": True, "PII scan (GDPR)": True, "safety classifier": False}
    assert json.loads(mcp_module.status_resource())["requests"] == 0


def test_recent_decisions_tool_reports_without_text(mcp_module):
    mcp_module.check_message("call +44 20 7946 0958")
    (d,) = mcp_module.recent_decisions(5)
    assert d["verdict"] == "redact" and d["source"] == "mcp"
    assert "7946" not in json.dumps(d)


def test_mcp_tools_are_callable(mcp_module):
    assert mcp_module.check_message("mail a.b@example.org")["verdict"] == "redact"
    assert mcp_module.governance_status()["requests"] == 1
    assert mcp_module.decision_matrix(load=0.5)["regime"] == "full checking"


def test_hook_endpoint_serves_checks_and_status(mcp_module):
    port = free_port()
    httpd = mcp_module.start_http(port)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/check",
                                     data=json.dumps({"text": "FLAGME"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert json.loads(resp.read())["verdict"] == "block"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=5) as resp:
            assert json.loads(resp.read())["requests"] == 1
    finally:
        httpd.shutdown()


# --- the hook ----------------------------------------------------------------------------------

@pytest.fixture()
def hook(monkeypatch):
    monkeypatch.setattr(hook_module, "PORT", free_port())  # nothing listening: local fallback
    return hook_module


def test_hook_reads_the_text_of_each_action(hook):
    assert hook.action_text("Bash", {"command": "ls -la"}) == "ls -la"
    assert hook.action_text("Write", {"file_path": "a", "content": "hi"}) == "hi"
    assert hook.action_text("MultiEdit", {"edits": [{"new_string": "a"}, {"new_string": "b"}]}) \
        == "a\nb"
    assert hook.action_text("Read", {"file_path": "a"}) == ""


def test_hook_reads_every_string_of_another_servers_tool(hook):
    inp = {"channel": "C1", "text": "hi", "blocks": [{"text": {"text": "call +44 20 7946 0958"}}]}
    assert "7946" in hook.action_text("mcp__slack__send_message", inp)
    out = hook.decide({"tool_name": "mcp__slack__send_message", "tool_input": inp})
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_fails_closed_when_the_check_cannot_run(hook, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert hook.main() == 2
    assert "blocked" in capsys.readouterr().err
    monkeypatch.setattr(hook, "FAIL_OPEN", True)
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert hook.main() == 0


def test_hook_splits_long_text_and_allows_noreply_addresses(hook):
    pieces = hook.chunks("line\n" * 2000)
    assert len(pieces) == 3 and all(len(p) <= hook.CHUNK for p in pieces)
    text = "Co-Authored-By: Claude <noreply@anthropic.com>, ask jane@acme.org"
    out = hook.without_allowed_addresses(text)
    assert "noreply@anthropic.com" not in out and "jane@acme.org" in out


def test_hook_asks_before_an_action_with_personal_data_even_without_the_gateway(hook):
    out = hook.decide({"tool_name": "Write",
                       "tool_input": {"file_path": "x.txt", "content": "call +44 20 7946 0958"}})
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask" and "telephone number" in spec[
        "permissionDecisionReason"]


def test_hook_lets_ordinary_actions_through(hook):
    assert hook.decide({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}) is None
    assert hook.decide({"tool_name": "Bash", "tool_input": {
        "command": "git commit -m 'x\n\nCo-Authored-By: C <noreply@anthropic.com>'"}}) is None


def test_hook_denies_through_the_gateway(hook, mcp_module, monkeypatch):
    port = free_port()
    httpd = mcp_module.start_http(port)
    monkeypatch.setattr(hook, "PORT", port)
    try:
        out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "echo FLAGME"}})
        spec = out["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"
        assert "FLAGME" not in spec["permissionDecisionReason"]
    finally:
        httpd.shutdown()


def test_the_hook_carries_the_checks_patterns():
    from governance_gateway import checks

    assert [(k, r.pattern) for k, r in hook_module._PII] == [
        (k, r.pattern) for k, r in checks.PII_KINDS]
