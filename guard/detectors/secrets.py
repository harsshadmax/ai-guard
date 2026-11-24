"""Secret-leak detector: known token formats, high-entropy strings, and planted canaries (certain leak)."""
import json
import math
import re
from collections import Counter

from shadowrun import config
from shadowrun.models import Finding

MAX_SCAN = 200_000
PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret", re.compile(r"(?i)aws.{0,20}secret.{0,20}[=:]\s*['\"]?([A-Za-z0-9/+=-]{30,})")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_(live|test)_[A-Za-z0-9]{10,}\b")),
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("url-credentials", re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,64}:[^\s@/]{4,128}@[^\s/]+")),
    ("assignment", re.compile(r"(?i)\b[\w.-]*(api[_-]?key|secret|token|passwd|password|private[_-]?key)[\w.-]*\s*[=:]\s*['\"]?([^\s'\"]{8,})")),
]
TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{24,200}")
HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


_CANARY_CACHE: dict = {"key": None, "value": {}}


def canaries() -> dict:
    """Planted fake secrets of the current workspace (cached on file mtime)."""
    p = config.GUARD_DIR / "canaries.json"
    try:
        key = (str(p), p.stat().st_mtime_ns)
        if _CANARY_CACHE["key"] != key:
            _CANARY_CACHE.update(key=key, value=json.loads(p.read_text()))
        return _CANARY_CACHE["value"]
    except (OSError, ValueError):
        return {}


def _flatten(obj, path="") -> list[tuple[str, str]]:
    if isinstance(obj, str):
        return [(path or "value", obj)]
    if isinstance(obj, dict):
        return [x for k, v in obj.items() for x in _flatten(v, f"{path}.{k}" if path else str(k))]
    if isinstance(obj, (list, tuple)):
        return [x for i, v in enumerate(obj) for x in _flatten(v, f"{path}[{i}]")]
    return []


def find_secrets(text: str) -> list[dict]:
    """-> [{kind, start, end, value}] (value is the raw match; callers must redact before storing)."""
    text = text[:MAX_SCAN]
    hits = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            hits.append({"kind": kind, "start": m.start(), "end": m.end(), "value": m.group(0)})
    covered = [(h["start"], h["end"]) for h in hits]
    for m in TOKEN.finditer(text):
        tok = m.group(0)
        if any(a <= m.start() < b for a, b in covered):
            continue
        if HEX_ONLY.match(tok) or UUID.match(tok) or tok.isalpha() or tok.isdigit():
            continue  # git SHAs, sha256 digests, UUIDs, words
        classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
        if classes >= 3 and entropy(tok) >= 4.2:
            hits.append({"kind": "high-entropy", "start": m.start(), "end": m.end(), "value": tok})
    for name, val in canaries().items():
        if name != "token" and isinstance(val, str) and len(val) >= 8:
            for m in re.finditer(re.escape(val), text):
                hits.append({"kind": f"canary:{name}", "start": m.start(), "end": m.end(), "value": val})
    tok = canaries().get("token")
    if tok:
        for m in re.finditer(rf"CANARY-?{re.escape(tok)}", text):
            hits.append({"kind": "canary:marker", "start": m.start(), "end": m.end(), "value": m.group(0)})
    return hits


def mask(v: str) -> str:
    return (v[:4] + "…" if len(v) > 8 else "") + f"[REDACTED {len(v)} chars]"


def scan_outbound(args: dict) -> list[Finding]:
    out, seen = [], set()
    for field, text in _flatten(args):
        for h in find_secrets(text):
            canary = h["kind"].startswith("canary")
            key = ("CANARY_EXFIL" if canary else "SECRET_IN_OUTBOUND", h["kind"], field)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                rule_id=key[0], severity="critical" if canary else "high", score=1.0 if canary else 0.9,
                detector="secrets", message=f"{'Planted canary' if canary else 'Secret'} ({h['kind']}) in outbound "
                                            f"argument '{field}': {mask(h['value'])}",
                evidence={"kind": h["kind"], "field": field, "preview": mask(h["value"])}))
    return out


def scan_result(text: str, source_id: str | None = None) -> list[Finding]:
    kinds = sorted({h["kind"] for h in find_secrets(text) if h["kind"] != "high-entropy"})
    if not kinds:
        return []
    return [Finding(rule_id="SECRET_IN_RESULT", severity="medium", score=0.9, detector="secrets",
                    message=f"Tool result contained secrets ({', '.join(kinds)}); redacted before the model saw it",
                    evidence={"kinds": kinds, "source_id": source_id})]
