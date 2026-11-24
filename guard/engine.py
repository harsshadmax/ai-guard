"""The guard: every tool call goes through guard(); nothing executes without an ALLOW (or a human approval).

normalise -> provenance/taint -> detectors (time budget) -> RBAC -> policy.decide_call ->
  BLOCK: stop | ASK: queue for a human | ALLOW: execute -> scan + redact result -> register as a source
Every step is recorded in the hash-chained audit log (payloads redacted)."""
import collections
import threading
import time

from shadowrun import audit, config, db, policy
from shadowrun.models import Finding

from . import detectors, provenance, rbac, redact, registry
from .detectors import anomaly, exfil, injection, integrity, pathrisk, secrets
from .models import STORE, Session, ToolCall, Verdict
from .tools import ToolError

EVENTS: collections.deque = collections.deque(maxlen=500)   # live feed for the dashboard (SSE)
_EVENT_ID = {"n": 0}
_EV_LOCK = threading.Lock()
_POLICY = {"key": None, "value": None}


def load_guard_policy() -> dict:
    p = config.GUARD_POLICY
    key = (str(p), p.stat().st_mtime_ns)
    if _POLICY["key"] != key:
        _POLICY.update(key=key, value=policy.load_policy(p))
    return _POLICY["value"]


def emit(kind: str, data: dict) -> None:
    with _EV_LOCK:
        _EVENT_ID["n"] += 1
        EVENTS.append({"id": _EVENT_ID["n"], "kind": kind, "ts": time.time(), **data})


def events_since(last_id: int) -> list[dict]:
    with _EV_LOCK:
        return [e for e in EVENTS if e["id"] > last_id]


# ------------------------------------------------------------------ explanation for humans
def _quote(span: dict | None, n: int = 200) -> str:
    t = ((span or {}).get("context") or (span or {}).get("text") or "").strip()
    t = t[:n] + ("…" if len(t) > n else "")
    return t.rstrip(" .")
def explain(v: Verdict, call: ToolCall, session: Session) -> str:
    if v.decision == "ALLOW":
        return f"Allowed {call.tool}."
    ids = v.rule_ids
    target = call.args.get("to") or call.args.get("path") or call.args.get("url") or call.args.get("command") \
        or call.args.get("sql") or ""
    head = f"{'Blocked' if v.decision == 'BLOCK' else 'Needs your approval'}: {call.tool}" + \
           (f" → {str(target)[:80]}" if target else "") + "."
    why = []
    inj = next((f for f in v.findings if f.rule_id == "INJECTION_IN_SESSION"), None)
    if inj and inj.span:
        why.append(f"The content this assistant read ({inj.span.get('origin', 'a document')}) contained a hidden "
                   f"instruction: “{_quote(inj.span)}”. "
                   f"The request did not come from you.")
    elif ids & {"TAINTED_SENSITIVE_READ", "TAINTED_EXTERNAL_SEND", "TAINTED_DESTRUCTIVE"}:
        why.append("This session read untrusted content just before trying this action.")
    if "ARG_FROM_UNTRUSTED" in ids:
        why.append("The target of this action was taken from untrusted content.")
    if ids & {"CANARY_EXFIL", "SECRET_IN_OUTBOUND"}:
        why.append("The outgoing data contains secrets.")
    if ids & {"EXFIL_DENYLISTED_DEST", "EXFIL_LOOKALIKE", "EXFIL_URL_BEACON"}:
        why.append("The destination is not trusted.")
    if any(i.startswith("RBAC_") for i in ids):
        why.append(f"Your role ({session.role}) does not allow this.")
    if ids & {"TOOL_RUG_PULL", "TOOL_POISONED_DESC", "TOOL_QUARANTINED", "TOOL_SHADOWING"}:
        why.append("The tool itself looks malicious (its description changed or contains instructions).")
    if ids & {"PATH_TRAVERSAL", "PATH_ESCAPE", "PATH_SYSTEM"}:
        why.append("The path points outside the allowed workspace.")
    if ids & {"DESTRUCTIVE_COMMAND", "OBFUSCATED_COMMAND"}:
        why.append("The command is destructive or obfuscated.")
    if not why:
        why.append(v.reason)
    tail = " The guard stopped it before it ran." if v.decision == "BLOCK" else \
        " Nothing has run yet; approve or deny it in the dashboard."
    return f"{head} {' '.join(why)}{tail}"


# ------------------------------------------------------------------ core
def _findings(call: ToolCall, session: Session, spec, pol: dict) -> tuple[list[Finding], dict, list[str]]:
    tool_class, path_class = registry.effective_class(spec, call.args)
    dest = exfil.dest_class(call.tool, call.args, pol)
    ctx = {"tool": call.tool, "tool_class": tool_class, "role": session.role, "taint": session.taint.value,
           "dest_class": dest, "path_class": path_class}
    jobs = {
        "pathrisk": lambda: pathrisk.scan(call.tool, call.args, workspace=spec.server == "builtin"),
        "exfil": lambda: exfil.scan(call.tool, call.args, pol) if tool_class == "external_send" else [],
        "secrets": lambda: secrets.scan_outbound(call.args) if tool_class in ("external_send", "exec") else [],
        "injection": lambda: _arg_injection(call),
        "integrity": lambda: integrity.observe(spec) if spec.server != "builtin" else [],
    }
    found = detectors.run_all(jobs, config.GUARD_TIMEOUT_MS)
    prov, src_ids = provenance.findings_for_call(session, call.tool, call.args, tool_class)
    found += prov
    found += anomaly.scan(session, tool_class)
    found += rbac.check(pol, session.role, call.tool, registry.rel_paths(call.args, spec.server == "builtin"),
                        registry.recipients(call.args),
                        session.call_times)
    return found, ctx, src_ids


def _arg_injection(call: ToolCall) -> list[Finding]:
    """Instructions smuggled through arguments to third-party tools (e.g. a 'notes' field)."""
    out = []
    for k, v in call.args.items():
        if isinstance(v, str) and len(v) > 40 and k not in ("body", "content"):
            fs, _ = injection.scan_content(v, origin=f"arg:{k}")
            out += [f for f in fs if f.score >= 0.8]
    return out


def check(call: ToolCall, session: Session) -> tuple[Verdict, object]:
    """Decide without executing. -> (verdict, spec or None)."""
    t0 = time.perf_counter()
    spec = registry.get(call.tool)
    if spec is None:
        f = Finding(rule_id="UNKNOWN_TOOL", severity="high", detector="engine", message=f"Unknown tool {call.tool!r}")
        d = policy.decide_call([f], {"tool": call.tool}, load_guard_policy())
        return Verdict(call_id=call.id, session_id=session.id, tool=call.tool, decision=d.decision, reason=d.reason,
                       matched_rules=d.matched_rules, findings=[f], latency_ms=(time.perf_counter() - t0) * 1000,
                       taint=session.taint.value), None
    try:
        pol = load_guard_policy()
        found, ctx, src_ids = _findings(call, session, spec, pol)
        d = policy.decide_call(found, ctx, pol)
    except Exception as e:  # fail closed
        found, ctx, src_ids = [Finding(rule_id="GUARD_ERROR", severity="high", detector="engine",
                                       message=f"{type(e).__name__}: {e}")], {"tool_class": spec.tool_class.value}, []
        d = policy.Decision(decision="BLOCK", matched_rules=[], findings=found, error=True,
                            reason=f"Guard error ({type(e).__name__}); blocked (fail closed).")
    v = Verdict(call_id=call.id, session_id=session.id, tool=call.tool, decision=d.decision, reason=d.reason,
                matched_rules=d.matched_rules, findings=found, latency_ms=(time.perf_counter() - t0) * 1000,
                taint=session.taint.value, tool_class=ctx.get("tool_class", ""), source_ids=src_ids)
    v.explanation = explain(v, call, session)
    return v, spec


def _execute(call: ToolCall, session: Session, spec, v: Verdict) -> None:
    try:
        res = spec.executor(**call.args)
    except ToolError as e:
        res = {"ok": False, "error": str(e)}
    except TypeError as e:
        res = {"ok": False, "error": f"bad arguments: {e}"}
    v.executed = True
    after_result(call, session, spec, v, res)


def after_result(call: ToolCall, session: Session, spec, v: Verdict, res) -> None:
    """Scan what the tool returned before the model sees it: secrets are redacted, content is registered."""
    text = res.get("content") if isinstance(res, dict) else res if isinstance(res, str) else None
    if session.guard_on:
        if isinstance(text, str) and text:
            v.post_findings += secrets.scan_result(text)
            red_text, red = redact.redact_text(text, entropy=False)
            if red:
                v.redactions += red
                res = {**res, "content": red_text} if isinstance(res, dict) else red_text
                audit.append("REDACTION_APPLIED", session.id, {"call_id": call.id, "redactions": red[:20]})
            pol = load_guard_policy()
            src = provenance.register_source(session, _origin(call), text, registry.result_trust(spec, call.args, pol))
            v.post_findings += src.findings
            v.source_ids.append(src.id)
            if src.findings:
                top = max(src.findings, key=lambda f: f.score)
                emit("alert", {"level": "warn", "session_id": session.id, "call_id": call.id,
                               "title": "Prompt injection detected in content",
                               "message": f"{_origin(call)} contains instructions aimed at the assistant: "
                                          f"“{_quote(top.span)}”. "
                                          f"Risky actions in this session are now restricted."})
    v.result = res


def _origin(call: ToolCall) -> str:
    a = call.args
    if call.tool in ("read_file", "list_dir"):
        return f"file:{a.get('path', '')}"
    if call.tool == "fetch_url":
        return f"url:{a.get('url', '')}"
    return f"tool:{call.tool}"


def _record(call: ToolCall, session: Session, v: Verdict) -> None:
    args_red, _ = redact.redact(call.args)
    session.history.append({"tool": call.tool, "tool_class": v.tool_class, "decision": v.decision, "ts": call.ts,
                            "path_class": next((pathrisk.path_class(p) for p in pathrisk.paths_in(call.args)), None)})
    db.insert_row("guard_calls", {
        "id": call.id, "session_id": session.id, "created_at": db.now_iso(), "tool": call.tool,
        "tool_class": v.tool_class, "args_redacted_json": args_red, "taint": v.taint, "source_ids_json": v.source_ids,
        "decision": v.decision, "reason": v.explanation or v.reason, "matched_rules_json": v.matched_rules,
        "latency_ms": round(v.latency_ms, 3), "executed": 1 if v.executed else 0,
        "guard_on": 1 if session.guard_on else 0})
    rows = [{"call_id": call.id, "source_id": (f.span or {}).get("source_id"), "session_id": session.id,
             "rule_id": f.rule_id, "severity": f.severity, "score": f.score, "detector": f.detector,
             "message": f.message, "span_json": f.span, "evidence_json": f.evidence}
            for f in v.findings + v.post_findings]
    for r in rows:
        db.insert_row("guard_findings", r)
    payload = {"call_id": call.id, "tool": call.tool, "args": args_red, "decision": v.decision,
               "rules": sorted(v.rule_ids), "matched": v.matched_rules, "latency_ms": round(v.latency_ms, 3),
               "taint": v.taint, "executed": v.executed}
    audit.append("VERDICT_ISSUED", session.id, payload)
    if any(f.rule_id.startswith("RBAC_") for f in v.findings):
        audit.append("RBAC_DENIED", session.id, {"call_id": call.id, "role": session.role, "tool": call.tool})
    if v.rule_ids & {"SECRET_IN_OUTBOUND", "CANARY_EXFIL"}:
        audit.append("SECRET_LEAK_DETECTED", session.id, {"call_id": call.id,
                                                          "rules": sorted(v.rule_ids & {"SECRET_IN_OUTBOUND", "CANARY_EXFIL"})})
    if v.executed:
        audit.append("TOOL_EXECUTED", session.id, {"call_id": call.id, "tool": call.tool})
    emit("call", {"session_id": session.id, "call_id": call.id, "tool": call.tool, "decision": v.decision,
                  "latency_ms": round(v.latency_ms, 2), "taint": v.taint, "rules": sorted(v.rule_ids)[:8]})
    if v.decision in ("BLOCK", "ASK") and session.guard_on:
        emit("alert", {"level": "block" if v.decision == "BLOCK" else "ask", "session_id": session.id,
                       "call_id": call.id, "approval_id": v.approval_id,
                       "title": "Action blocked" if v.decision == "BLOCK" else "Approval needed",
                       "message": v.explanation})


def guard(call: ToolCall, session: Session | None = None) -> Verdict:
    """Entry point for every tool call."""
    session = session or STORE.get(call.session_id)
    if session is None:
        return Verdict(call_id=call.id, session_id=call.session_id, tool=call.tool, decision="BLOCK",
                       reason="Unknown session; blocked (fail closed).", explanation="Unknown session.")
    session.call_times = [t for t in session.call_times if time.time() - t < 60] + [time.time()]
    audit.append("TOOL_CALL_RECEIVED", session.id, {"call_id": call.id, "tool": call.tool,
                                                    "args": redact.redact(call.args)[0]})
    if not session.guard_on:  # baseline for the demo / eval: the assistant without a guard
        spec = registry.get(call.tool)
        v = Verdict(call_id=call.id, session_id=session.id, tool=call.tool, decision="UNGUARDED",
                    reason="Guard is off", tool_class=spec.tool_class.value if spec else "")
        if spec:
            _execute(call, session, spec, v)
        _record(call, session, v)
        return v
    v, spec = check(call, session)
    if v.decision == "ALLOW" and spec is not None:
        _execute(call, session, spec, v)
    elif v.decision == "ASK":
        from . import approvals
        v.approval_id = approvals.create(call, session, v)
        v.explanation = explain(v, call, session)
    _record(call, session, v)
    return v


def resume_approved(approval_id: str) -> Verdict | None:
    """Run a call a human approved (called by approvals.resolve)."""
    from . import approvals
    item = approvals.PENDING.pop(approval_id, None)
    if not item:
        return None
    call, session, v = item
    spec = registry.get(call.tool)
    if spec is not None:
        _execute(call, session, spec, v)
        v.decision = "ALLOW"
        v.reason = "Approved by a human."
        db.update_row("guard_calls", "id", call.id, executed=1, decision="ALLOW",
                      reason=f"Approved by a human. {v.explanation}")
        audit.append("TOOL_EXECUTED", session.id, {"call_id": call.id, "tool": call.tool, "approved": approval_id})
        emit("call", {"session_id": session.id, "call_id": call.id, "tool": call.tool, "decision": "ALLOW",
                      "latency_ms": round(v.latency_ms, 2), "taint": v.taint, "rules": ["APPROVED"]})
    return v
