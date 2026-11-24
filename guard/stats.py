"""Read models for the dashboard: KPI cards, live feed, incident (session) detail. Pure SQL over guard_* tables."""
import json
from datetime import datetime, timedelta, timezone

from shadowrun import db

WINDOWS = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}


def _since(window: str) -> str:
    d = WINDOWS.get(window)
    return (datetime.now(timezone.utc) - d).isoformat() if d else ""


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * len(v)))], 2)


def cards(window: str = "all") -> dict:
    since = _since(window)
    rows = db.query("SELECT decision, latency_ms, guard_on FROM guard_calls WHERE created_at >= ?", (since,))
    guarded = [r for r in rows if r["guard_on"]]
    count = lambda d: sum(1 for r in guarded if r["decision"] == d)  # noqa: E731
    lat = [r["latency_ms"] for r in guarded if r["latency_ms"] is not None]
    inj = db.query("SELECT COUNT(DISTINCT source_id) n FROM guard_findings f JOIN guard_sources s ON s.id=f.source_id "
                   "WHERE f.rule_id LIKE 'INJECTION%' AND s.created_at >= ?", (since,))[0]["n"]
    pending = db.query("SELECT COUNT(*) n FROM guard_approvals WHERE state='pending'")[0]["n"]
    return {"window": window, "calls": len(guarded), "allowed": count("ALLOW"), "asked": count("ASK"),
            "blocked": count("BLOCK"), "unguarded": len(rows) - len(guarded), "injections": inj,
            "pending_approvals": pending, "p50_ms": _pct(lat, 0.5), "p95_ms": _pct(lat, 0.95), "p99_ms": _pct(lat, 0.99)}


def by_rule(limit: int = 12) -> list[dict]:
    return db.query("SELECT f.rule_id, COUNT(*) n FROM guard_findings f JOIN guard_calls c ON c.id=f.call_id "
                    "WHERE c.decision IN ('BLOCK','ASK') GROUP BY f.rule_id ORDER BY n DESC LIMIT ?", (limit,))


def _call_row(r: dict) -> dict:
    r = dict(r)
    for k in ("args_redacted_json", "matched_rules_json", "source_ids_json"):
        try:
            r[k.replace("_json", "")] = json.loads(r.get(k) or "null")
        except ValueError:
            r[k.replace("_json", "")] = None
    return r


def feed(limit: int = 40, session_id: str | None = None) -> list[dict]:
    sql = ("SELECT c.*, s.role, s.agent_id FROM guard_calls c LEFT JOIN guard_sessions s ON s.id=c.session_id ")
    if session_id:
        rows = db.query(sql + "WHERE c.session_id=? ORDER BY c.created_at DESC LIMIT ?", (session_id, limit))
    else:
        rows = db.query(sql + "ORDER BY c.created_at DESC LIMIT ?", (limit,))
    out = []
    for r in rows:
        r = _call_row(r)
        r["rules"] = [x["rule_id"] for x in db.query(
            "SELECT DISTINCT rule_id FROM guard_findings WHERE call_id=? ORDER BY rule_id", (r["id"],))]
        out.append(r)
    return out


def incidents(limit: int = 30) -> list[dict]:
    return db.query(
        "SELECT s.*, SUM(c.decision='BLOCK') blocked, SUM(c.decision='ASK') asked, COUNT(c.id) calls, "
        "MAX(c.created_at) last_at FROM guard_sessions s LEFT JOIN guard_calls c ON c.session_id=s.id "
        "GROUP BY s.id ORDER BY s.created_at DESC LIMIT ?", (limit,))


def session_detail(session_id: str) -> dict | None:
    rows = db.query("SELECT * FROM guard_sessions WHERE id=?", (session_id,))
    if not rows:
        return None
    sources = db.query("SELECT * FROM guard_sources WHERE session_id=? ORDER BY created_at", (session_id,))
    for s in sources:
        s["findings"] = []
        for f in db.query("SELECT * FROM guard_findings WHERE source_id=? AND call_id IN "
                          "(SELECT id FROM guard_calls WHERE session_id=?) ORDER BY score DESC", (s["id"], session_id)):
            f["span"] = json.loads(f.get("span_json") or "null")
            if f["rule_id"].startswith("INJECTION") and f["rule_id"] != "INJECTION_IN_SESSION" and not any(x["rule_id"] == f["rule_id"] and
                                                                  (x["span"] or {}).get("text") == (f["span"] or {}).get("text")
                                                                  for x in s["findings"]):
                s["findings"].append(f)
    calls = list(reversed(feed(500, session_id)))
    for c in calls:
        c["findings"] = db.query("SELECT rule_id, severity, score, detector, message FROM guard_findings "
                                 "WHERE call_id=? AND (source_id IS NULL OR rule_id NOT LIKE 'INJECTION_%' "
                                 "OR rule_id='INJECTION_IN_SESSION') ORDER BY score DESC", (c["id"],))
    audit_rows = db.query("SELECT id, ts, event_type, hash FROM audit_log WHERE run_id=? ORDER BY id", (session_id,))
    return {"session": rows[0], "sources": sources, "calls": calls, "audit": audit_rows}
