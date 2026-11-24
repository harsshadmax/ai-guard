"""HTTP proxy and dashboard API for the AI tool guard (mounted into the existing FastAPI app, localhost only).
Mutating routes need the same X-Demo-Token header as the rest of Shadow-Run."""
import asyncio
import json
import threading

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from shadowrun import audit, db, policy

from . import approvals, engine, integrity_api, provenance, registry, scenarios, stats, tools
from .models import STORE, Session, ToolCall

router = APIRouter(prefix="/api/v1/guard")
MAX_BODY = 256 * 1024
DEMO_LOCK = threading.Lock()


def need_token(request: Request, x_demo_token: str | None = Header(default=None)):
    from shadowrun import api as core  # lazy: core imports this module
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        raise HTTPException(413, "Request too large")
    core.need_token(x_demo_token)


class SessionIn(BaseModel):
    user_id: str = Field("demo-user", max_length=80)
    role: str = Field("analyst", max_length=40)
    agent_id: str = Field("api", max_length=80)
    guard_on: bool = True
    task: str = Field("", max_length=2000)


class CallIn(BaseModel):
    session_id: str = Field(max_length=40)
    tool: str = Field(max_length=80)
    args: dict = Field(default_factory=dict)


class EvalIn(BaseModel):
    tool: str = Field(max_length=80)
    args: dict = Field(default_factory=dict)
    role: str = Field("analyst", max_length=40)
    taint: str = Field("trusted", pattern="^(trusted|internal|untrusted)$")


class DecisionIn(BaseModel):
    approve: bool
    note: str = Field("", max_length=500)


class DemoIn(BaseModel):
    scenario: str = Field("hidden-text", max_length=40)
    mode: str = Field("both", pattern="^(on|off|both)$")


def _verdict_json(v) -> dict:
    d = v.model_dump()
    d["rules"] = sorted(v.rule_ids)
    return d


@router.post("/session", dependencies=[Depends(need_token)])
def create_session(body: SessionIn):
    s = provenance.new_session(**body.model_dump())
    return {"session_id": s.id, "role": s.role, "guard_on": s.guard_on}


@router.post("/call", dependencies=[Depends(need_token)])
def guarded_call(body: CallIn):
    """The proxy endpoint: an agent sends every tool call here instead of calling the tool."""
    s = STORE.get(body.session_id)
    if s is None:
        raise HTTPException(404, "Unknown session (create one with POST /api/v1/guard/session)")
    if len(json.dumps(body.args, default=str)) > MAX_BODY:
        raise HTTPException(413, "Arguments too large")
    return _verdict_json(engine.guard(ToolCall(session_id=s.id, tool=body.tool, args=body.args), s))


@router.post("/evaluate", dependencies=[Depends(need_token)])
def what_if(body: EvalIn):
    """What would the guard decide? Nothing is executed or stored."""
    from .models import Source, Trust
    s = Session(role=body.role, guard_on=True)
    if body.taint != "trusted":
        s.sources.append(Source(session_id=s.id, origin="what-if", trust=Trust(body.taint), text=""))
        s.raise_taint(Trust(body.taint))
    v, _ = engine.check(ToolCall(session_id=s.id, tool=body.tool, args=body.args), s)
    return {"decision": v.decision, "reason": v.reason, "explanation": v.explanation, "matched_rules": v.matched_rules,
            "findings": [f.model_dump() for f in v.findings], "latency_ms": v.latency_ms}


@router.get("/calls")
def list_calls(session_id: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    if session_id:
        return db.query("SELECT * FROM guard_calls WHERE session_id=? ORDER BY created_at DESC LIMIT ?", (session_id, limit))
    return db.query("SELECT * FROM guard_calls ORDER BY created_at DESC LIMIT ?", (limit,))


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    d = stats.session_detail(session_id)
    if not d:
        raise HTTPException(404, "Unknown session")
    return d


@router.get("/approvals")
def list_approvals(state: str | None = "pending"):
    return approvals.list_items(state)


@router.post("/approvals/{approval_id}", dependencies=[Depends(need_token)])
def resolve_approval(approval_id: str, body: DecisionIn):
    r = approvals.resolve(approval_id, body.approve, by="dashboard", note=body.note)
    if not r["ok"]:
        raise HTTPException(409, r["error"])
    return r


@router.get("/tools")
def list_tools():
    return integrity_api.tools_view()


@router.post("/tools/{name}/approve", dependencies=[Depends(need_token)])
def approve_tool(name: str):
    if not integrity_api.approve(name):
        raise HTTPException(404, "Unknown tool")
    return {"ok": True}


@router.get("/stats")
def guard_stats(window: str = "all"):
    return stats.cards(window)


@router.get("/sink")
def sink(limit: int = 50):
    return tools.sink_events()[-max(1, min(limit, 500)):]


@router.get("/policy")
def get_policy():
    p = engine.load_guard_policy()
    return {"roles": p.get("roles"), "destinations": p.get("destinations"), "trust": p.get("trust"),
            "rules": p["rules"], "lint": policy.lint_policy(engine.config.GUARD_POLICY)}


@router.get("/scenarios")
def list_scenarios():
    return [{"id": k, "title": v["title"], "task": v["task"]} for k, v in scenarios.SCENARIOS.items()]


@router.post("/demo", dependencies=[Depends(need_token)])
async def run_demo(body: DemoIn):
    if body.scenario not in scenarios.SCENARIOS:
        raise HTTPException(404, "Unknown scenario")

    def work():
        with DEMO_LOCK:
            out = {}
            for on in ([False, True] if body.mode == "both" else [body.mode == "on"]):
                registry.reset_workspace()
                lines = []
                r = scenarios.run(body.scenario, on, log=lines.append)
                r["log"] = lines
                out["on" if on else "off"] = r
            return out
    return await asyncio.to_thread(work)


@router.post("/reset", dependencies=[Depends(need_token)])
def reset():
    with DEMO_LOCK:
        db.demo_reset()
        registry.reset_workspace()
        STORE.sessions.clear()
        approvals.PENDING.clear()
        from .detectors import integrity
        integrity.reset_cache()
    return {"ok": True}


@router.get("/audit/verify")
def verify_audit():
    return audit.verify()


@router.get("/stream")
async def stream(request: Request, last_id: int = 0):
    """Server-sent events: tool-call verdicts and alerts as they happen."""
    async def gen():
        last = last_id
        yield "retry: 2000\n\n"
        idle = 0
        while not await request.is_disconnected():
            evs = engine.events_since(last)
            for e in evs:
                last = e["id"]
                yield f"id: {e['id']}\nevent: {e['kind']}\ndata: {json.dumps(e, default=str)}\n\n"
            idle = 0 if evs else idle + 1
            if idle and idle % 30 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})
