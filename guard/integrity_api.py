"""Tool catalogue with integrity state, for the dashboard and API."""
from shadowrun import audit, db

from . import registry
from .detectors import integrity


def tools_view() -> list[dict]:
    base = {r["tool"]: r for r in db.query("SELECT * FROM guard_tool_baselines")}
    out = []
    for name, spec in sorted(registry.all_specs().items()):
        b = base.get(name)
        out.append({"tool": name, "server": spec.server, "tool_class": spec.tool_class.value,
                    "description": spec.description,
                    "pinned": bool(b), "approved": bool(b and b["approved"]), "quarantined": bool(b and b["quarantined"]),
                    "desc_sha256": (b or {}).get("desc_sha256", "")[:16], "first_seen": (b or {}).get("first_seen"),
                    "last_changed": (b or {}).get("last_changed"),
                    "changed_now": bool(b) and integrity._h(spec.description) != b["desc_sha256"]})
    return out


def approve(name: str) -> bool:
    spec = registry.get(name)
    if spec is None:
        return False
    if integrity.baseline(name) is None:
        integrity.observe(spec)
    integrity.approve(name, spec)
    audit.append("TOOL_INTEGRITY_CHANGED", None, {"tool": name, "action": "re-approved by admin"})
    return True
