"""Prompt-injection detector. Runs on content entering the model's context and on tool descriptions.

Layers: (1) hidden-content extraction (guard.normalize), (2) regex patterns from policies/injection_patterns.yaml,
(3) optional local classifier (GUARD_USE_CLASSIFIER=1; not shipped, rules-only otherwise).
It only produces scored findings with the exact span; the policy decides."""
import functools
import os
import re

import yaml

from shadowrun import config
from shadowrun.models import Finding

from .. import normalize

MAX_SCAN = 100_000


@functools.lru_cache(maxsize=4)
def _load(path: str) -> list[dict]:
    data = yaml.safe_load(open(path, encoding="utf-8"))
    out = []
    for p in data["patterns"]:
        out.append({**p, "rx": re.compile(p["pattern"], re.I | re.S)})
    return out


def patterns() -> list[dict]:
    return _load(str(config.GUARD_PATTERNS))


def _scan(text: str, where: str, source_id: str | None) -> list[Finding]:
    out = []
    for p in patterns():
        m = p["rx"].search(text[:MAX_SCAN])
        if not m:
            continue
        snippet = text[max(0, m.start() - 40): m.end() + 80]
        out.append(Finding(
            rule_id=p["rule"], severity="high" if p["score"] >= 0.75 else "medium", score=p["score"],
            detector="injection", message=f"{p['id']}: instruction-like text in {where}",
            evidence={"pattern": p["id"], "where": where, "match": m.group(0)[:200]},
            span={"source_id": source_id, "where": where, "start": m.start(), "end": m.end(),
                  "text": m.group(0)[:300], "context": snippet[:400]}))
    return out


def scan_content(raw: str, origin: str = "", source_id: str | None = None) -> tuple[list[Finding], dict]:
    """-> (findings, extracted). Visible-text matches, hidden-text matches (boosted), decoded-layer matches."""
    ex = normalize.extract(raw, origin)
    findings = _scan(ex["visible"], "visible text", source_id)
    seen = {(f.rule_id, f.evidence["pattern"]) for f in findings}
    for kind, text in ex["hidden"]:
        for f in _scan(text, f"hidden content ({kind})", source_id):
            f.span["context"] = text[:400]  # the whole hidden segment is what the human never saw
            if (f.rule_id, f.evidence["pattern"]) in seen and kind != "unicode-tags":
                continue
            findings.append(f)
            findings.append(Finding(
                rule_id="INJECTION_HIDDEN_TEXT", severity="high", score=min(1.0, f.score + 0.05), detector="injection",
                message=f"Instruction hidden from the human reader ({kind}): \"{f.span['text'][:120]}\"",
                evidence={"kind": kind, "pattern": f.evidence["pattern"]}, span=f.span))
    for kind, text in ex["decoded"]:
        for f in _scan(text, f"{kind}-encoded text", source_id):
            f.span["context"] = text[:400]
            findings.append(f)
            findings.append(Finding(
                rule_id="INJECTION_ENCODED", severity="high", score=f.score, detector="injection",
                message=f"Instruction hidden in {kind} encoding: \"{f.span['text'][:120]}\"",
                evidence={"kind": kind, "pattern": f.evidence["pattern"]}, span=f.span))
    if os.environ.get("GUARD_USE_CLASSIFIER") == "1":
        findings += _classifier(ex["text"], source_id)
    return _dedupe(findings), ex


def _dedupe(fs: list[Finding]) -> list[Finding]:
    best: dict[tuple, Finding] = {}
    for f in fs:
        k = (f.rule_id, f.evidence.get("pattern"), f.evidence.get("kind"))
        if k not in best or f.score > best[k].score:
            best[k] = f
    return list(best.values())


def _classifier(text: str, source_id: str | None) -> list[Finding]:  # pragma: no cover - optional
    """Hook for a local prompt-injection classifier. Absent model -> no findings (rules still apply)."""
    try:
        from transformers import pipeline  # type: ignore
    except Exception:
        return []
    clf = pipeline("text-classification", model=os.environ.get("GUARD_CLASSIFIER_MODEL",
                                                                  "protectai/deberta-v3-base-prompt-injection-v2"))
    r = clf(text[:2000])[0]
    if r["label"].upper().startswith("INJ") and r["score"] > 0.5:
        return [Finding(rule_id="INJECTION_CLASSIFIER", severity="medium", score=float(r["score"]),
                        detector="classifier", message="Classifier flagged injection-like content",
                        span={"source_id": source_id, "text": text[:200]})]
    return []
