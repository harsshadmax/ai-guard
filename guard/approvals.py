"""Human-in-the-loop queue for ASK verdicts. Approve runs the call once; deny or timeout never runs it."""
import threading
import time
from datetime import datetime, timedelta, timezone

from shadowrun import audit, config, db

from .models import new_id

PENDING: dict[str, tuple] = {}   # approval id -> (call, session, verdict) kept in memory until resolved
_LOCK = threading.Lock()


def create(call, session, verdict) -> str:
    aid = new_id("apr")
    now = datetime.now(timezone.utc)
    with _LOCK:
        PENDING[aid] = (call, session, verdict)
    db.insert_row("guard_approvals", {
        "id": aid, "call_id": call.id, "session_id": session.id, "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=config.GUARD_APPROVAL_TTL_S)).isoformat(), "state": "pending"})
    audit.append("APPROVAL_REQUESTED", session.id, {"approval_id": aid, "call_id": call.id, "tool": call.tool,
                                                    "rules": sorted(verdict.rule_ids)})
    return aid


def expire_old() -> int:
    """Pending items past their deadline become 'expired' (= denied)."""
    now = datetime.now(timezone.utc).isoformat()
    rows = db.query("SELECT id, session_id FROM guard_approvals WHERE state='pending' AND expires_at < ?", (now,))
    for r in rows:
        db.update_row("guard_approvals", "id", r["id"], state="expired", resolved_at=now, resolved_by="timeout")
        with _LOCK:
            PENDING.pop(r["id"], None)
        audit.append("APPROVAL_RESOLVED", r["session_id"], {"approval_id": r["id"], "state": "expired"})
    return len(rows)


def list_items(state: str | None = "pending") -> list[dict]:
    expire_old()
    sql = ("SELECT a.*, c.tool, c.reason, c.args_redacted_json, c.matched_rules_json FROM guard_approvals a "
           "LEFT JOIN guard_calls c ON c.id = a.call_id")
    if state:
        return db.query(sql + " WHERE a.state=? ORDER BY a.created_at DESC", (state,))
    return db.query(sql + " ORDER BY a.created_at DESC LIMIT 100")


def resolve(aid: str, approve: bool, by: str = "user", note: str = "") -> dict:
    """-> {ok, state, error?, verdict?}. Each item can be resolved exactly once."""
    expire_old()
    rows = db.query("SELECT * FROM guard_approvals WHERE id=?", (aid,))
    if not rows:
        return {"ok": False, "error": "unknown approval"}
    if rows[0]["state"] != "pending":
        return {"ok": False, "error": f"already {rows[0]['state']}"}
    state = "approved" if approve else "denied"
    now = datetime.now(timezone.utc).isoformat()
    db.update_row("guard_approvals", "id", aid, state=state, resolved_by=by[:80], resolved_at=now, note=note[:500])
    audit.append("APPROVAL_RESOLVED", rows[0]["session_id"], {"approval_id": aid, "state": state, "by": by[:80]})
    out = {"ok": True, "state": state}
    if approve:
        from . import engine
        v = engine.resume_approved(aid)
        out["verdict"] = v.model_dump(exclude={"findings", "post_findings"}) if v else None
    else:
        with _LOCK:
            PENDING.pop(aid, None)
    return out


def wait(aid: str, timeout_s: float) -> str:
    """Block until resolved or timeout (used by agents that can wait). -> final state."""
    end = time.time() + timeout_s
    while time.time() < end:
        rows = db.query("SELECT state FROM guard_approvals WHERE id=?", (aid,))
        if rows and rows[0]["state"] != "pending":
            return rows[0]["state"]
        time.sleep(0.25)
    return "pending"
