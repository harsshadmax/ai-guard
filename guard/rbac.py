"""Role-based access control for tools, paths, recipients and call volume (roles live in guard.yaml)."""
import time
from fnmatch import fnmatch

from shadowrun.models import Finding


def _allowed(value: str, patterns: list[str]) -> bool:
    """Ordered globs; '!pattern' excludes. Last matching pattern wins."""
    ok = False
    forms = [value] if value in ("", ".") or "@" in value else [value, value.rstrip("/") + "/"]
    for p in patterns or []:
        if p.startswith("!"):
            if fnmatch(value, p[1:]):
                ok = False
        elif any(fnmatch(v, p) for v in forms):
            ok = True
    return ok


def check(policy: dict, role: str, tool: str, rel_paths: list[str], recipients: list[str],
          call_times: list[float] | None = None) -> list[Finding]:
    roles = policy.get("roles") or {}
    r = roles.get(role)
    if r is None:
        return [Finding(rule_id="RBAC_UNKNOWN_ROLE", severity="high", score=1.0, detector="rbac",
                        message=f"Unknown role {role!r}", evidence={"role": role})]
    out = []
    if not _allowed(tool, r.get("tools") or []):
        out.append(Finding(rule_id="RBAC_TOOL_DENIED", severity="high", score=1.0, detector="rbac",
                           message=f"Role '{role}' may not use tool '{tool}'", evidence={"role": role, "tool": tool}))
    for p in rel_paths:
        if not _allowed(p, r.get("paths") or []):
            out.append(Finding(rule_id="RBAC_PATH_DENIED", severity="high", score=1.0, detector="rbac",
                               message=f"Role '{role}' may not access '{p}'", evidence={"role": role, "path": p}))
    for d in recipients:
        if not _allowed(d.lower(), [x.lower() for x in r.get("recipients") or []]):
            out.append(Finding(rule_id="RBAC_RECIPIENT_DENIED", severity="high", score=1.0, detector="rbac",
                               message=f"Role '{role}' may not send to {d}", evidence={"role": role, "dest": d}))
    limit = r.get("max_calls_per_min")
    if limit and call_times is not None:
        now = time.time()
        if sum(1 for t in call_times if now - t < 60) > limit:
            out.append(Finding(rule_id="RBAC_VOLUME_EXCEEDED", severity="high", score=1.0, detector="rbac",
                               message=f"Role '{role}' exceeded {limit} tool calls per minute",
                               evidence={"role": role, "limit": limit}))
    return out
