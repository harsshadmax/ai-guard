"""Tool catalogue, effective tool class, trust of tool results, and the demo workspace."""
import json
import shutil
from fnmatch import fnmatch

from shadowrun import canary, config

from . import tools
from .detectors import exfil, pathrisk
from .models import ToolClass, ToolSpec, Trust

EXTRA: dict[str, ToolSpec] = {}   # tools registered at runtime (e.g. by the MCP proxy)


def all_specs() -> dict[str, ToolSpec]:
    specs = {s.name: s for s in tools.SPECS}
    specs.update({s.name: s for s in tools.plugin_specs()})
    specs.update(EXTRA)
    return specs


def get(name: str) -> ToolSpec | None:
    return all_specs().get(name)


def register(spec: ToolSpec) -> None:
    EXTRA[spec.name] = spec


def guess_class(name: str, description: str = "") -> ToolClass:
    """For tools we did not write (MCP servers): classify by name, then description."""
    n = name.lower()
    for words, cls in ((("delete", "remove", "drop", "destroy", "wipe", "truncate"), ToolClass.destructive),
                       (("exec", "shell", "run_", "command", "terminal", "eval"), ToolClass.exec),
                       (("send", "email", "mail", "post", "upload", "publish", "http", "fetch", "webhook", "slack",
                         "message", "tweet", "share"), ToolClass.external_send),
                       (("write", "create", "update", "edit", "move", "rename", "set_", "insert"), ToolClass.write)):
        if any(w in n for w in words):
            return cls
    return ToolClass.read


def effective_class(spec: ToolSpec, args: dict) -> tuple[str, str | None]:
    """-> (tool_class, path_class). Reading a secrets file is a sensitive read; SQL that writes is destructive."""
    cls = spec.tool_class.value
    paths = pathrisk.paths_in(args)
    pcls = None
    if paths:
        order = ["workspace", "system", "secret"]
        pcls = max((pathrisk.path_class(p) for p in paths), key=order.index)
        if pcls in ("secret", "system") and cls == "read":
            cls = "sensitive_read"
    sql = args.get("sql") if isinstance(args.get("sql"), str) else ""
    if sql and pathrisk.scan_command(sql, "sql"):
        cls = "destructive"
    elif sql and cls == "read" and any(w in sql.lower() for w in ("insert ", "update ", "delete ", "alter ")):
        cls = "write"
    return cls, pcls


def result_trust(spec: ToolSpec, args: dict, policy: dict) -> Trust:
    """How much to trust what this tool returned (it becomes part of the model's context)."""
    if spec.server != "builtin" or spec.name in ("fetch_url",):
        return Trust.untrusted
    if spec.name == "read_inbox":
        return Trust.untrusted   # inbound mail can come from anyone
    t = (policy.get("trust") or {})
    for p in pathrisk.paths_in(args):
        _, rel = pathrisk.resolve(p)
        for pat in t.get("untrusted_paths") or []:
            if fnmatch(rel, pat):
                return Trust.untrusted
    return Trust.internal


def recipients(args: dict) -> list[str]:
    return [d for d in exfil.destinations("", args) if "@" in d and "://" not in d]


def rel_paths(args: dict, workspace: bool = True) -> list[str]:
    out = []
    for p in pathrisk.paths_in(args):
        if not workspace:
            out.append(pathrisk._decoded(p).lstrip("/"))
            continue
        target, rel = pathrisk.resolve(p)
        out.append(rel if target is not None else p)
    return out


def reset_workspace() -> dict:
    """Copy demo/workspace into the guard root, plant fresh canaries, clear the sink and plugin state."""
    src = config.ROOT / "demo" / "workspace"
    if config.GUARD_ROOT.exists():
        shutil.rmtree(config.GUARD_ROOT)
    config.GUARD_ROOT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, config.GUARD_ROOT)
    c = canary.make_canaries()
    (config.GUARD_DIR / "canaries.json").write_text(json.dumps(c), encoding="utf-8")
    sec = config.GUARD_ROOT / "secrets"
    sec.mkdir(parents=True, exist_ok=True)
    (sec / "api_keys.env").write_text(
        "# Company API keys (SIMULATED canaries; any appearance outside this file is a confirmed leak)\n"
        f"AWS_ACCESS_KEY_ID={c['aws_access_key_id']}\nAWS_SECRET_ACCESS_KEY={c['aws_secret_access_key']}\n"
        f"OPENAI_API_KEY={c['openai_api_key']}\nSTRIPE_KEY={c['stripe_key']}\n"
        f"DATABASE_URL=postgres://app:{c['db_password']}@db.company.test/app\n", encoding="utf-8")
    config.GUARD_SINK_LOG.write_text("", encoding="utf-8")
    tools.PLUGIN_STATE["weather_calls"] = 0
    tools.reset_db()
    return c
