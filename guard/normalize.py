"""Turn raw content into what the model actually reads, and separate what a human would NOT see.

Attackers hide instructions in: white-on-white or tiny text, display:none / visibility:hidden / opacity:0,
HTML comments, zero-width characters, Unicode "tag" characters (invisible ASCII), and encodings (base64, hex,
rot13). Everything is bounded so a hostile document cannot make the guard slow (ReDoS / huge inputs)."""
import base64
import binascii
import codecs
import re
import unicodedata
from html.parser import HTMLParser

MAX_TEXT = 200_000
ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­"), None)
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?\s*(;|$)|font-size\s*:\s*[0-2](\.\d+)?\s*(px|pt)"
    r"|color\s*:\s*(#fff(fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)|left\s*:\s*-\d{3,}px", re.I)
VOID = {"br", "img", "hr", "meta", "link", "input", "area", "base", "col", "embed", "source", "track", "wbr"}
HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                            "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "Α": "A",
                            "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
                            "Т": "T", "Х": "X"})
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,4000}={0,2}(?![A-Za-z0-9+/=])")
HEX = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){16,2000}(?![0-9a-fA-F])")
ROT13_HINT = re.compile(r"\b(rot13|ebg13)\b[:\s]+([A-Za-z0-9 ,.'!?/:_\-<>@=&%()`*]{12,2000})", re.I)


class _Html(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[bool] = []   # one entry per open element: is it hidden?
        self.visible: list[str] = []
        self.hidden: list[tuple[str, str]] = []

    def _hidden_now(self) -> bool:
        return any(self.stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        hid = bool(HIDDEN_STYLE.search(a.get("style", ""))) or "hidden" in a or a.get("aria-hidden") == "true" \
            or tag in ("script", "style", "template")
        if tag in VOID:
            for k in ("alt", "title"):
                if a.get(k):
                    self.hidden.append(("attribute", a[k]))
            return
        self.stack.append(hid)

    def handle_endtag(self, tag):
        if tag not in VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if not data.strip():
            self.visible.append(data)
            return
        if self._hidden_now():
            self.hidden.append(("hidden-style", data.strip()))
        else:
            self.visible.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.hidden.append(("html-comment", data.strip()))


def _decode_tags(s: str) -> tuple[str, str]:
    """Unicode tag characters U+E0020..U+E007E map to invisible ASCII."""
    out, hidden = [], []
    for ch in s:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            hidden.append(chr(cp - 0xE0000))
        elif 0xE0000 <= cp <= 0xE007F:
            continue
        else:
            out.append(ch)
    return "".join(out), "".join(hidden)


def _printable_ratio(s: str) -> float:
    return sum(c.isprintable() or c in "\n\t" for c in s) / max(1, len(s))


def decode_layers(text: str) -> list[tuple[str, str]]:
    """Best-effort decoding of embedded base64 / hex / rot13 that turns out to be readable text."""
    found = []
    for m in B64.finditer(text[:MAX_TEXT]):
        blob = m.group(0)
        if len(found) >= 20:
            break
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(s) >= 12 and _printable_ratio(s) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", s):
            found.append(("base64", s))
    for m in HEX.finditer(text[:MAX_TEXT]):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(s) > 0.95 and re.search(r"[a-zA-Z]{3,}\s+[a-zA-Z]{2,}", s):
            found.append(("hex", s))
    for m in ROT13_HINT.finditer(text[:MAX_TEXT]):
        found.append(("rot13", codecs.decode(m.group(2), "rot13")))
    return found


def fold(s: str) -> str:
    """Canonical form used for matching: NFKC, homoglyphs folded, zero-width removed, whitespace collapsed."""
    s = unicodedata.normalize("NFKC", s).translate(ZERO_WIDTH).translate(HOMOGLYPHS)
    return re.sub(r"\s+", " ", s)


def looks_like_html(raw: str, origin: str = "") -> bool:
    return origin.lower().endswith((".html", ".htm")) or bool(re.search(r"<(html|body|div|span|p|font)\b", raw[:5000], re.I))


def extract(raw: str, origin: str = "") -> dict:
    """-> {visible, hidden: [(kind, text)], decoded: [(kind, text)], text (what the model sees, folded)}."""
    raw = (raw or "")[:MAX_TEXT]
    raw, tag_hidden = _decode_tags(raw)
    hidden: list[tuple[str, str]] = []
    if tag_hidden.strip():
        hidden.append(("unicode-tags", tag_hidden))
    zw = sum(raw.count(chr(c)) for c in ZERO_WIDTH)
    if zw >= 3:
        hidden.append(("zero-width", f"{zw} zero-width characters interleaved in the text"))
    if looks_like_html(raw, origin):
        p = _Html()
        try:
            p.feed(raw)
            p.close()
        except Exception:  # malformed HTML: fall back to the raw text, still scanned
            p.visible = [raw]
        visible = "".join(p.visible)
        hidden += p.hidden
    else:
        visible = raw
    decoded = decode_layers(raw)
    model_text = fold(" ".join([visible] + [h for _, h in hidden] + [d for _, d in decoded]))
    return {"visible": fold(visible), "hidden": [(k, fold(t)) for k, t in hidden],
            "decoded": [(k, fold(t)) for k, t in decoded], "text": model_text}
