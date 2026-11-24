"""Where is data going? Classify destinations and catch lookalike domains and data-in-URL beacons."""
import re
from fnmatch import fnmatch
from urllib.parse import parse_qsl, unquote, urlsplit

from shadowrun.models import Finding

from .. import normalize

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DEST_ARGS = ("to", "cc", "bcc", "recipient", "recipients", "url", "endpoint", "webhook", "host")


def _lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def destinations(tool: str, args: dict) -> list[str]:
    """Email addresses and URLs a call would send data to."""
    out = []
    for k in DEST_ARGS:
        v = args.get(k)
        vals = v if isinstance(v, list) else [v] if isinstance(v, str) else []
        for x in vals:
            out += EMAIL.findall(x) if "@" in x and "://" not in x else [x.strip()]
    return [d for d in out if d]


def _host(d: str) -> str:
    if "@" in d and "://" not in d:
        return d.rsplit("@", 1)[1].lower()
    return (urlsplit(d if "://" in d else "http://" + d).hostname or "").lower()


def classify(dest: str, policy: dict) -> str:
    """internal | allowlisted | denylisted | unknown (strictest pattern wins: denylist first)."""
    dests = policy.get("destinations") or {}
    d = dest.lower()
    for cls in ("denylisted", "internal", "allowlisted"):
        for pat in dests.get(cls) or []:
            if fnmatch(d, pat.lower()) or fnmatch(_host(d), pat.lower().split("@")[-1].split("://")[-1].split("/")[0]):
                return cls
    return "unknown"


def dest_class(tool: str, args: dict, policy: dict) -> str | None:
    ds = destinations(tool, args)
    if not ds:
        return None
    order = ["internal", "allowlisted", "unknown", "denylisted"]
    return max((classify(d, policy) for d in ds), key=order.index)


def _internal_hosts(policy: dict) -> list[str]:
    hosts = []
    for pat in (policy.get("destinations") or {}).get("internal") or []:
        h = pat.split("@")[-1].split("://")[-1].split("/")[0].lstrip("*.")
        if h:
            hosts.append(h.lower())
    return hosts


def scan(tool: str, args: dict, policy: dict) -> list[Finding]:
    out = []
    internal = _internal_hosts(policy)
    for d in destinations(tool, args):
        cls = classify(d, policy)
        host = _host(d)
        folded = normalize.fold(host)
        if cls == "denylisted":
            out.append(Finding(rule_id="EXFIL_DENYLISTED_DEST", severity="high", score=1.0, detector="exfil",
                               message=f"Destination {d} is on the deny list", evidence={"dest": d}))
        elif cls == "unknown":
            look = next((h for h in internal if host != h and (folded == h or _lev(host, h) <= 2)), None)
            if look:
                out.append(Finding(rule_id="EXFIL_LOOKALIKE", severity="high", score=0.95, detector="exfil",
                                   message=f"{host} looks like the company domain {look}", evidence={"dest": d}))
            out.append(Finding(rule_id="EXFIL_UNKNOWN_DEST", severity="medium", score=0.7, detector="exfil",
                               message=f"Data would go to an unknown destination: {d}", evidence={"dest": d}))
        if "://" in d:
            q = urlsplit(d).query
            for k, v in parse_qsl(q, keep_blank_values=True):
                v = unquote(v)
                if len(v) >= 32 or re.search(r"(key|token|secret|pass|data|d|q|c)$", k, re.I) and len(v) >= 16:
                    out.append(Finding(rule_id="EXFIL_URL_BEACON", severity="high", score=0.85, detector="exfil",
                                       message=f"URL carries data in parameter '{k}' ({len(v)} chars)",
                                       evidence={"dest": d.split("?")[0], "param": k}))
                    break
    for field in ("body", "content", "text", "message"):
        v = args.get(field)
        if isinstance(v, str) and re.search(r"!\[[^\]]{0,100}\]\(\s*https?://[^\s)]{1,300}\?[^\s)]{8,}\)", v):
            out.append(Finding(rule_id="EXFIL_URL_BEACON", severity="high", score=0.85, detector="exfil",
                               message=f"Markdown image with data in its URL in '{field}' (auto-loading beacon)",
                               evidence={"field": field}))
    return out
