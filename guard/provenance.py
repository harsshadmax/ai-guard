"""Provenance and taint tracking: where did the content that is steering this tool call come from?

Every tool result the model reads is registered as a Source with a trust level. A session's taint is the
highest trust level it has ingested. Tool calls made after untrusted content get taint findings, and any
argument (recipient, path, URL, command) that literally appears in untrusted content is flagged
ARG_FROM_UNTRUSTED: the strongest sign that an injected instruction, not the user, chose the target."""
import hashlib
import re

from shadowrun import audit, db
from shadowrun.models import Finding

from . import normalize
from .detectors import injection
from .detectors.exfil import EMAIL
from .models import STORE, Session, Source, Trust

TARGET_ARGS = ("path", "file", "to", "cc", "bcc", "recipient", "url", "command", "cmd", "sql", "query", "target")
RISKY = {"sensitive_read", "external_send", "destructive", "exec", "write"}


def new_session(**kw) -> Session:
    s = Session(**kw)
    STORE.put(s)
    db.insert_row("guard_sessions", {"id": s.id, "created_at": db.now_iso(), "user_id": s.user_id, "role": s.role,
                                     "agent_id": s.agent_id, "guard_on": 1 if s.guard_on else 0,
                                     "max_taint": s.taint.value, "task": s.task[:500]})
    audit.append("SESSION_STARTED", s.id, {"user": s.user_id, "role": s.role, "agent": s.agent_id,
                                           "guard_on": s.guard_on, "task": s.task[:200]})
    return s


def register_source(session: Session, origin: str, raw: str, trust: Trust, scan: bool = True) -> Source:
    findings, ex = injection.scan_content(raw, origin=origin) if scan else ([], normalize.extract(raw, origin))
    src = Source(session_id=session.id, origin=origin, trust=trust, text=ex["text"],
                 hidden_text=" | ".join(f"[{k}] {t}" for k, t in ex["hidden"] + ex["decoded"])[:4000],
                 sha256=hashlib.sha256((raw or "").encode("utf-8", "replace")).hexdigest())
    for f in findings:
        f.span = {**(f.span or {}), "source_id": src.id, "origin": origin}
    src.findings = findings
    session.sources.append(src)
    raised = session.raise_taint(trust)
    db.insert_row("guard_sources", {"id": src.id, "session_id": session.id, "created_at": db.now_iso(),
                                    "origin": origin, "trust": trust.value, "sha256": src.sha256,
                                    "preview": ex["visible"][:600], "hidden_text": src.hidden_text})
    audit.append("CONTENT_INGESTED", session.id, {"source_id": src.id, "origin": origin, "trust": trust.value,
                                                  "sha256": src.sha256, "hidden_segments": len(ex["hidden"])})
    if raised:
        db.update_row("guard_sessions", "id", session.id, max_taint=session.taint.value)
        audit.append("TAINT_ASSIGNED", session.id, {"taint": session.taint.value, "source_id": src.id})
    if findings:
        audit.append("INJECTION_DETECTED", session.id, {
            "source_id": src.id, "origin": origin,
            "rules": sorted({f.rule_id for f in findings}),
            "spans": [f.span.get("text", "")[:200] for f in findings if f.span][:5]})
    return src


def _values(args: dict) -> list[tuple[str, str]]:
    out = []
    for k in TARGET_ARGS:
        v = args.get(k)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and len(x.strip()) >= 4:
                out.append((k, x.strip()))
    return out


def _appears(value: str, text: str) -> tuple[int, int] | None:
    v = normalize.fold(value).lower()
    t = text.lower()
    i = t.find(v)
    if i >= 0:
        return i, i + len(v)
    if "@" in v:  # recipient lists: compare each address
        for e in EMAIL.findall(v):
            j = t.find(e)
            if j >= 0:
                return j, j + len(e)
    base = re.split(r"[/\\]", v)[-1]
    if len(base) >= 6 and "." in base:  # "secrets/api_keys.env" mentioned as "api_keys.env"
        j = t.find(base)
        if j >= 0:
            return j, j + len(base)
    return None


def findings_for_call(session: Session, tool: str, args: dict, tool_class: str) -> tuple[list[Finding], list[str]]:
    """-> (findings, ids of the untrusted sources that influenced this call)."""
    out: list[Finding] = []
    src_ids: list[str] = []
    untrusted = session.untrusted_sources
    for k, v in _values(args):
        if k == "url" and "?" not in v:
            continue  # a plain link taken from a page is normal browsing
        for s in untrusted:
            hit = _appears(v, s.text)
            if hit:
                src_ids.append(s.id)
                out.append(Finding(
                    rule_id="ARG_FROM_UNTRUSTED", severity="high", score=0.9, detector="provenance",
                    message=f"Argument '{k}'={v[:80]!r} was taken from untrusted content ({s.origin})",
                    evidence={"arg": k, "source_id": s.id, "origin": s.origin},
                    span={"source_id": s.id, "origin": s.origin, "start": hit[0], "end": hit[1],
                          "text": s.text[hit[0]:hit[1]], "context": s.text[max(0, hit[0] - 120): hit[1] + 60]}))
                break
    if session.taint == Trust.untrusted and tool_class in RISKY:
        src_ids += [s.id for s in untrusted]
        origins = ", ".join(sorted({s.origin for s in untrusted}))[:200]
        rule = {"sensitive_read": "TAINTED_SENSITIVE_READ", "external_send": "TAINTED_EXTERNAL_SEND",
                "destructive": "TAINTED_DESTRUCTIVE", "exec": "TAINTED_DESTRUCTIVE", "write": "TAINTED_WRITE"}[tool_class]
        sev = {"TAINTED_DESTRUCTIVE": "critical", "TAINTED_WRITE": "low"}.get(rule, "high")
        if tool == "fetch_url":
            sev = "medium"  # following links is normal browsing; data in the URL is caught by EXFIL_URL_BEACON
        out.append(Finding(rule_id=rule, severity=sev, score=0.8, detector="provenance",
                           message=f"'{tool}' ({tool_class}) after the session read untrusted content: {origins}",
                           evidence={"sources": sorted(set(src_ids))[:10]}))
        injected = [f for s in untrusted for f in s.findings if f.rule_id.startswith("INJECTION")]
        if injected:
            top = max(injected, key=lambda f: f.score)
            out.append(Finding(rule_id="INJECTION_IN_SESSION", severity="high", score=top.score, detector="provenance",
                               message=f"This session ingested a prompt injection: \"{(top.span or {}).get('text', '')[:120]}\"",
                               evidence={"source_id": (top.span or {}).get("source_id")}, span=top.span))
    return out, sorted(set(src_ids))
