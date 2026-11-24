"""Dashboard pages and htmx fragments for the AI tool guard. Reuses the core Jinja environment (autoescape ON:
documents, arguments and tool descriptions are attacker-controlled text)."""
import json

from fastapi import APIRouter, HTTPException, Request

from shadowrun import audit, db
from shadowrun.ui import _ctx, templates

from . import approvals, engine, integrity_api, scenarios, stats

router = APIRouter()


def _page(request: Request, name: str, page: str, **kw):
    db.init_db()
    return templates.TemplateResponse(request, name, _ctx(request, page, section="guard", **kw))


def _frag(request: Request, name: str, **kw):
    db.init_db()
    return templates.TemplateResponse(request, name, kw)


@router.get("/guard")
def feed_page(request: Request):
    return _page(request, "guard_feed.html", "guard-feed")


@router.get("/guard/incidents")
def incidents_page(request: Request):
    return _page(request, "guard_incidents.html", "guard-incidents", incidents=stats.incidents())


@router.get("/guard/session/{session_id}")
def session_page(request: Request, session_id: str):
    d = stats.session_detail(session_id)
    if not d:
        raise HTTPException(404, "Unknown session")
    return _page(request, "guard_session.html", "guard-incidents", d=d, chain=audit.verify())


@router.get("/guard/approvals")
def approvals_page(request: Request):
    return _page(request, "guard_approvals.html", "guard-approvals")


@router.get("/guard/policy")
def policy_page(request: Request):
    p = engine.load_guard_policy()
    from shadowrun import policy
    return _page(request, "guard_policy.html", "guard-policy", pol=p,
                 lint=policy.lint_policy(engine.config.GUARD_POLICY))


@router.get("/guard/tools")
def tools_page(request: Request):
    return _page(request, "guard_tools.html", "guard-tools", tools=integrity_api.tools_view())


@router.get("/guard/demo")
def demo_page(request: Request):
    return _page(request, "guard_demo.html", "guard-demo", scenarios=scenarios.SCENARIOS)


# ---------------------------------------------------------------- fragments
@router.get("/ui/guard/cards")
def frag_cards(request: Request):
    return _frag(request, "_guard_cards.html", c=stats.cards("all"), rules=stats.by_rule())


@router.get("/ui/guard/feed")
def frag_feed(request: Request, session_id: str | None = None):
    return _frag(request, "_guard_feed.html", rows=stats.feed(40, session_id))


@router.get("/ui/guard/approvals")
def frag_approvals(request: Request):
    items = approvals.list_items("pending")
    for i in items:
        try:
            i["args"] = json.loads(i.get("args_redacted_json") or "{}")
        except ValueError:
            i["args"] = {}
    return _frag(request, "_guard_approvals.html", items=items, recent=approvals.list_items(None)[:10])


@router.get("/ui/guard/pending-count")
def frag_pending(request: Request):
    n = stats.cards("all")["pending_approvals"]
    return _frag(request, "_guard_pending.html", n=n)
