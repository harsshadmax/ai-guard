"""Mask secrets in tool arguments, results and audit payloads. Returns what was redacted (never the value)."""
from .detectors.secrets import find_secrets, mask


def redact_text(text: str, entropy: bool = True) -> tuple[str, list[dict]]:
    """entropy=False keeps generic high-entropy strings (used for document content, where base64 blobs and
    IDs are common; known token formats and canaries are always masked)."""
    hits = sorted((h for h in find_secrets(text) if entropy or h["kind"] != "high-entropy"),
                  key=lambda h: (h["start"], -h["end"]))
    out, last, red = [], 0, []
    for h in hits:
        if h["start"] < last:
            continue
        out.append(text[last:h["start"]])
        out.append(mask(h["value"]))
        red.append({"kind": h["kind"], "preview": mask(h["value"])})
        last = h["end"]
    out.append(text[last:])
    return "".join(out), red


def redact(obj):
    """-> (copy of obj with secrets masked, redactions)."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        acc, out = [], {}
        for k, v in obj.items():
            out[k], r = redact(v)
            acc += r
        return out, acc
    if isinstance(obj, (list, tuple)):
        acc, out = [], []
        for v in obj:
            x, r = redact(v)
            out.append(x)
            acc += r
        return out, acc
    return obj, []
