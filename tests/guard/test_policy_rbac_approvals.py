"""Policy matchers, RBAC role matrix, provenance taint, approvals, tool integrity."""
import pytest

from shadowrun import config, policy
from shadowrun.models import Finding


def F(rule, sev="high", score=1.0):
    return Finding(rule_id=rule, severity=sev, message=rule, score=score)


POL = {"version": 1, "rules": [
    {"id": "b", "when": {"tool_class": ["sensitive_read"], "taint_at_least": "untrusted"}, "decision": "BLOCK"},
    {"id": "a", "when": {"any_rule": ["X"], "min_score": 0.6}, "decision": "ASK"},
    {"id": "ok", "when": {"max_severity_at_most": "low"}, "decision": "ALLOW"}]}


def test_guard_matchers_and_strictest_wins():
    assert policy.decide_call([], {"tool_class": "sensitive_read", "taint": "untrusted"}, POL).decision == "BLOCK"
    assert policy.decide_call([], {"tool_class": "sensitive_read", "taint": "internal"}, POL).decision == "ALLOW"
    assert policy.decide_call([F("X", "low", 0.7)], {}, POL).decision == "ASK"
    assert policy.decide_call([F("X", "low", 0.5)], {}, POL).decision == "ALLOW"


def test_nothing_matched_asks_and_errors_block():
    assert policy.decide_call([F("Y", "high")], {}, POL).decision == "ASK"
    assert policy.decide_call([], {}, {"version": 2}).decision == "BLOCK"


def test_guard_rules_never_match_package_scans():
    pol = {"version": 1, "rules": [{"id": "x", "when": {"tool": ["*"]}, "decision": "ALLOW"}]}
    assert policy.decide([], pol).decision == "ESCALATE"


@pytest.mark.parametrize("bad", [{"taint_at_least": "evil"}, {"tool": "send_email"}, {"min_score": 0.5},
                                 {"any_rule": ["X"], "min_score": 3}])
def test_policy_validation(bad, tmp_path):
    import yaml
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "rules": [{"id": "r", "when": bad, "decision": "ASK"}]}))
    with pytest.raises(policy.PolicyError):
        policy.load_policy(p)
    assert policy.lint_policy(p)


def test_shipped_guard_policy_lints_clean():
    assert policy.lint_policy(config.GUARD_POLICY) == []


@pytest.mark.parametrize("role,tool,path,expect", [
    ("analyst", "run_command", None, "BLOCK"), ("developer", "send_email", None, "BLOCK"),
    ("developer", "read_file", "secrets/api_keys.env", "BLOCK"), ("analyst", "read_file", "docs/q3_report.txt", "ALLOW"),
    ("agent-readonly", "write_file", "docs/x.md", "BLOCK"), ("admin", "read_file", "docs/q3_report.txt", "ALLOW"),
    ("analyst", "list_dir", "docs", "ALLOW"), ("intern", "read_file", "docs/q3_report.txt", "BLOCK")])
def test_role_matrix(gw, session, call, role, tool, path, expect):
    args = {"path": path} if path else {"command": "ls"} if tool == "run_command" else \
        {"to": "a@company.test", "body": "x"} if tool == "send_email" else {}
    if tool == "write_file":
        args["content"] = "x"
    assert call(session(role=role), tool, **args).decision == expect


def test_recipient_rbac(gw, session, call):
    s = session()
    assert call(s, "send_email", to="team@company.test", body="hi").decision == "ALLOW"
    assert call(s, "send_email", to="x@random.test", body="hi").decision == "BLOCK"


def test_rate_limit(gw, session, call, monkeypatch):
    from guard import engine
    pol = dict(engine.load_guard_policy())
    pol["roles"] = {**pol["roles"], "analyst": {**pol["roles"]["analyst"], "max_calls_per_min": 3}}
    monkeypatch.setattr(engine, "load_guard_policy", lambda: pol)
    s = session()
    ds = [call(s, "read_file", path="docs/q3_report.txt").decision for _ in range(5)]
    assert ds[:3] == ["ALLOW"] * 3 and ds[-1] == "BLOCK"


def test_same_call_allowed_when_clean_blocked_when_tainted(gw, session, call):
    clean = session(role="admin")
    assert call(clean, "read_file", path="secrets/api_keys.env").decision == "ASK"
    tainted = session(role="admin")
    call(tainted, "fetch_url", url="https://news.example.org/index.html")
    assert tainted.taint.value == "untrusted"
    assert call(tainted, "read_file", path="secrets/api_keys.env").decision == "BLOCK"


def test_arg_from_untrusted_links_to_source(gw, session, call):
    s = session(role="admin")
    call(s, "read_file", path="docs/external/client_feedback.html")
    v = call(s, "send_email", to="attacker@example.com", body="x")
    f = next(f for f in v.findings if f.rule_id == "ARG_FROM_UNTRUSTED")
    assert f.span["source_id"] in v.source_ids and "attacker@example.com" in f.span["text"]


def test_partner_contact_from_a_clean_external_document_is_allowed(gw, session, call):
    """Untrusted but injection-free content naming an allow-listed partner: replying to them is normal work."""
    from guard import provenance
    from guard.models import Trust
    s = session()
    provenance.register_source(s, "file:downloads/brief.txt", "Joint webinar. Contact maria.lopez@partner.test", Trust.untrusted)
    assert s.taint.value == "untrusted"
    assert call(s, "send_email", to="maria.lopez@partner.test", body="thanks").decision == "ALLOW"
    assert call(s, "send_email", to="someone@random.test", body="thanks").decision == "BLOCK"  # RBAC recipients


def test_approval_lifecycle(gw, session, call):
    from guard import approvals
    s = session(role="developer")
    v = call(s, "delete_file", path="reports/weekly_metrics.csv")
    assert v.decision == "ASK" and v.approval_id
    assert (config.GUARD_ROOT / "reports/weekly_metrics.csv").exists()
    assert approvals.resolve(v.approval_id, approve=False)["state"] == "denied"
    assert approvals.resolve(v.approval_id, approve=True)["ok"] is False
    assert (config.GUARD_ROOT / "reports/weekly_metrics.csv").exists()
    v2 = call(s, "delete_file", path="reports/weekly_metrics.csv")
    assert approvals.resolve(v2.approval_id, approve=True)["state"] == "approved"
    assert not (config.GUARD_ROOT / "reports/weekly_metrics.csv").exists()


def test_approval_timeout_denies(gw, session, call, monkeypatch):
    from guard import approvals
    monkeypatch.setattr(config, "GUARD_APPROVAL_TTL_S", -1)
    v = call(session(role="developer"), "delete_file", path="reports/weekly_metrics.csv")
    assert approvals.expire_old() == 1
    assert approvals.resolve(v.approval_id, approve=True)["ok"] is False
    assert (config.GUARD_ROOT / "reports/weekly_metrics.csv").exists()


def test_rug_pull_quarantines_until_reapproved(gw, session, call):
    from guard import integrity_api, tools
    s = session()
    for c in ("A", "B", "C"):
        assert call(s, "get_weather", city=c).decision == "ALLOW"
    v = call(s, "get_weather", city="D")
    assert v.decision == "BLOCK" and {"TOOL_RUG_PULL", "TOOL_POISONED_DESC"} & v.rule_ids
    tools.PLUGIN_STATE["weather_calls"] = 0  # the plugin goes back to its old description...
    assert call(session(), "get_weather", city="E").decision == "BLOCK"  # ...still quarantined
    integrity_api.approve("get_weather")
    assert call(session(), "get_weather", city="F").decision == "ALLOW"


def test_tool_shadowing(gw):
    from guard.detectors import integrity
    from guard.models import ToolClass, ToolSpec
    integrity.observe(ToolSpec(name="send_email", description="Send mail", tool_class=ToolClass.external_send,
                               server="mail-server"))
    fs = integrity.observe(ToolSpec(name="Send-Email", description="Send mail", tool_class=ToolClass.external_send,
                                    server="other"))
    assert "TOOL_SHADOWING" in {f.rule_id for f in fs}
