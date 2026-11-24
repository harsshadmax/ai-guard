"""Tool integrity: detect malicious plugins.

* rug pull: a tool's description or input schema changes after it was approved -> quarantine.
* tool poisoning: the description itself carries instructions for the model.
* shadowing: a new tool whose name is confusable with an approved tool from another server."""
import hashlib
import json

from shadowrun import audit, db
from shadowrun.models import Finding

from .. import normalize
from . import injection


def _h(x) -> str:
    return hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()


def _canon(name: str) -> str:
    return normalize.fold(name).lower().replace("-", "_").replace(" ", "_")


def baseline(name: str) -> dict | None:
    rows = db.query("SELECT * FROM guard_tool_baselines WHERE tool=?", (name,))
    return rows[0] if rows else None


_SEEN: dict[str, tuple] = {}   # tool -> (desc_h, schema_h, findings): skip DB work while nothing changes


def reset_cache() -> None:
    _SEEN.clear()


def observe(spec, approve_new: bool = True) -> list[Finding]:
    """Record or compare a tool's advertised surface. Returns findings (empty when unchanged)."""
    desc_h, schema_h = _h(spec.description), _h(spec.input_schema)
    hit = _SEEN.get(spec.name)
    if hit and hit[:2] == (desc_h, schema_h):
        return list(hit[2])
    out = _observe(spec, approve_new, desc_h, schema_h)
    _SEEN[spec.name] = (desc_h, schema_h, out)
    return list(out)


def _observe(spec, approve_new: bool, desc_h: str, schema_h: str) -> list[Finding]:
    out: list[Finding] = []
    pf, _ = injection.scan_content(spec.description, origin=f"tool:{spec.name}")
    if pf:
        out.append(Finding(rule_id="TOOL_POISONED_DESC", severity="high", score=max(f.score for f in pf),
                           detector="integrity", message=f"Tool '{spec.name}' description contains instructions "
                                                         f"for the model: \"{pf[0].span['text'][:120]}\"",
                           evidence={"tool": spec.name, "server": spec.server}, span=pf[0].span))
    b = baseline(spec.name)
    now = db.now_iso()
    if b is None:
        others = db.query("SELECT tool, server FROM guard_tool_baselines WHERE approved=1")
        for o in others:
            if o["server"] != spec.server and _canon(o["tool"]) == _canon(spec.name):
                out.append(Finding(rule_id="TOOL_SHADOWING", severity="high", score=0.9, detector="integrity",
                                   message=f"Tool '{spec.name}' from {spec.server} shadows '{o['tool']}' "
                                           f"from {o['server']}", evidence={"tool": spec.name}))
        approved = approve_new and not out
        db.insert_row("guard_tool_baselines", {
            "tool": spec.name, "server": spec.server, "desc_sha256": desc_h, "schema_sha256": schema_h,
            "approved": 1 if approved else 0, "first_seen": now, "last_changed": now,
            "quarantined": 0 if approved else 1, "description": spec.description[:2000]})
        return out
    if b["desc_sha256"] != desc_h or b["schema_sha256"] != schema_h:
        what = [w for w, c in (("description", b["desc_sha256"] != desc_h), ("schema", b["schema_sha256"] != schema_h)) if c]
        if not b["quarantined"]:
            db.update_row("guard_tool_baselines", "tool", spec.name, quarantined=1, last_changed=now,
                          description=spec.description[:2000])
            audit.append("TOOL_INTEGRITY_CHANGED", None, {"tool": spec.name, "server": spec.server, "changed": what,
                                                          "old_desc_sha256": b["desc_sha256"], "new_desc_sha256": desc_h})
        out.append(Finding(rule_id="TOOL_RUG_PULL", severity="critical", score=1.0, detector="integrity",
                           message=f"Tool '{spec.name}' changed its {' and '.join(what)} after it was approved; "
                                   f"quarantined until an admin re-approves it",
                           evidence={"tool": spec.name, "changed": what}))
    elif b["quarantined"]:
        out.append(Finding(rule_id="TOOL_QUARANTINED", severity="high", score=1.0, detector="integrity",
                           message=f"Tool '{spec.name}' is quarantined", evidence={"tool": spec.name}))
    return out


def approve(name: str, spec=None) -> None:
    """Admin re-approval: pin the current surface as the new baseline."""
    fields = {"approved": 1, "quarantined": 0, "last_changed": db.now_iso()}
    if spec is not None:
        fields.update(desc_sha256=_h(spec.description), schema_sha256=_h(spec.input_schema),
                      description=spec.description[:2000])
    db.update_row("guard_tool_baselines", "tool", name, **fields)
    _SEEN.pop(name, None)
