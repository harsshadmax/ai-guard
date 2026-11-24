"""Path and command risk: secret files, traversal and escapes, destructive or obfuscated commands."""
import posixpath
import re
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import unquote

from shadowrun import config
from shadowrun.models import Finding

from .. import normalize

SECRET_GLOBS = ["*.env", ".env", "*/.env*", "*.pem", "*.key", "*id_rsa*", "*id_ed25519*", "*credentials*",
                "secrets/*", "*/secrets/*", "*secret*", "*api_key*", "*apikey*", "*.p12", "*.pfx", "*.kdbx",
                "*.npmrc", "*.pypirc", "*.netrc", "*/.aws/*", "*/.ssh/*", ".ssh/*", ".aws/*", "*.token",
                "*auth_token*", "*access_token*"]
SYSTEM_PREFIXES = ("/etc/", "/proc/", "/sys/", "/root/", "/var/", "c:/windows", "c:/users/", "~", "/home/")
DESTRUCTIVE = [
    ("rm-rf", re.compile(r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|-r\s+-f|-f\s+-r)\b", re.I)),
    ("win-del", re.compile(r"\b(del|erase)\s+(/[sqf]\s*){1,3}|\brmdir\s+/s\b|\bRemove-Item\b.{0,60}-Recurse", re.I)),
    ("format", re.compile(r"\b(mkfs(\.\w+)?|format\s+[a-z]:|diskpart|dd\s+if=)", re.I)),
    ("sql-drop", re.compile(r"\b(drop\s+(table|database|schema)|truncate\s+table)\b", re.I)),
    ("sql-mass-delete", re.compile(r"\bdelete\s+from\s+\w+\s*(;|$)(?!.*\bwhere\b)", re.I)),
    ("sql-mass-update", re.compile(r"\bupdate\s+\w+\s+set\b(?!.*\bwhere\b)", re.I)),
    ("shutdown", re.compile(r"\b(shutdown|reboot|halt|poweroff)\b(\s+-[a-z]+)*", re.I)),
    ("git-force", re.compile(r"\bgit\s+(push\s+.*--force|reset\s+--hard|clean\s+-[a-z]*f)", re.I)),
    ("fork-bomb", re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:")),
]
OBFUSCATED = [
    ("pipe-to-shell", re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|]{0,200}\|\s*(ba|z|da)?sh\b|\|\s*iex\b", re.I)),
    ("b64-exec", re.compile(r"base64\s+(-d|--decode)[^|]{0,100}\|\s*(ba|z)?sh|powershell(\.exe)?\s+.*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}", re.I)),
    ("reverse-shell", re.compile(r"/dev/tcp/|\bnc\s+(-e|-c)\b|\bsocat\b.*exec", re.I)),
    ("eval", re.compile(r"\b(eval|exec)\s*\(\s*(base64|atob|bytes\.fromhex|__import__)", re.I)),
]
PATH_ARGS = ("path", "file", "filename", "src", "dst", "target", "directory", "dir")


def _decoded(p: str) -> str:
    for _ in range(3):
        q = unquote(p)
        if q == p:
            break
        p = q
    return normalize.fold(p).replace("\\", "/").strip()


def paths_in(args: dict) -> list[str]:
    return [args[k] for k in PATH_ARGS if isinstance(args.get(k), str)]


def path_class(p: str) -> str:
    d = _decoded(p).lower()
    base = posixpath.basename(d.rstrip("/"))
    if any(fnmatch(d, g) or fnmatch(base, g) for g in SECRET_GLOBS):
        return "secret"
    if d.startswith(SYSTEM_PREFIXES) or re.match(r"^[a-z]:/", d):
        return "system"
    return "workspace"


def resolve(p: str, root: Path | None = None) -> tuple[Path | None, str]:
    """-> (resolved path inside root, rel) or (None, reason). Symlinks are resolved, then checked."""
    root = (root or config.GUARD_ROOT).resolve()
    d = _decoded(p)
    if d.startswith("/") or re.match(r"^[a-zA-Z]:/", d) or d.startswith("~"):
        return None, "absolute path outside the workspace"
    target = (root / d).resolve()
    try:
        rel = target.relative_to(root)
    except ValueError:
        return None, "path escapes the workspace"
    return target, rel.as_posix()


def scan_paths(args: dict, root: Path | None = None, workspace: bool = True) -> list[Finding]:
    out = []
    for p in paths_in(args):
        d = _decoded(p)
        if ".." in d.split("/") or p != d and ".." in d:
            out.append(Finding(rule_id="PATH_TRAVERSAL", severity="high", score=0.95, detector="pathrisk",
                               message=f"Path traversal in {p!r}", evidence={"path": p}))
        target, why = resolve(p, root) if workspace else (True, "")
        if target is None:
            out.append(Finding(rule_id="PATH_ESCAPE", severity="high", score=1.0, detector="pathrisk",
                               message=f"{p!r}: {why}", evidence={"path": p}))
        cls = path_class(p)
        if cls == "secret":
            out.append(Finding(rule_id="PATH_SECRET", severity="medium", score=0.9, detector="pathrisk",
                               message=f"{p!r} is a secrets file", evidence={"path": p}))
        elif cls == "system":
            out.append(Finding(rule_id="PATH_SYSTEM", severity="high", score=0.9, detector="pathrisk",
                               message=f"{p!r} is a system location", evidence={"path": p}))
    return out


def scan_command(text: str, field: str = "command") -> list[Finding]:
    t = normalize.fold(text)[:20_000]
    out = []
    for name, rx in DESTRUCTIVE:
        if rx.search(t):
            out.append(Finding(rule_id="DESTRUCTIVE_COMMAND", severity="critical", score=0.95, detector="pathrisk",
                               message=f"Destructive operation ({name}) in '{field}'", evidence={"kind": name}))
            break
    for name, rx in OBFUSCATED:
        if rx.search(t):
            out.append(Finding(rule_id="OBFUSCATED_COMMAND", severity="high", score=0.9, detector="pathrisk",
                               message=f"Obfuscated or remote-code command ({name}) in '{field}'",
                               evidence={"kind": name}))
            break
    return out


def scan(tool: str, args: dict, root: Path | None = None, workspace: bool = True) -> list[Finding]:
    """workspace=False for third-party (MCP) tools: their paths live on another server, so only traversal,
    secret-file and system-path checks apply, not 'inside the demo workspace'."""
    out = scan_paths(args, root, workspace)
    for field in ("command", "cmd", "sql", "script", "query"):
        if isinstance(args.get(field), str):
            out += scan_command(args[field], field)
    return out
