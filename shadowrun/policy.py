"""Policy engine: all rules evaluated, strictest decision wins (BLOCK > ESCALATE/ASK > ALLOW). Fails closed.
ESCALATE (pip deep scan) is treated as denied; ASK (AI tool guard) waits for a human, and times out to denied.
No LLM is involved: detectors only produce scored findings, this module makes the decision."""
from fnmatch import fnmatch
from pathlib import Path

import yaml
from pydantic import BaseModel

from . import config
from .models import SEVERITY_ORDER, Finding

STRICTNESS = {"ALLOW": 0, "ESCALATE": 1, "ASK": 1, "BLOCK": 2}
TAINT_ORDER = {"trusted": 0, "internal": 1, "untrusted": 2}
GUARD_WHEN_KEYS = {"tool", "tool_class", "role", "taint_at_least", "min_score", "dest_class", "path_class"}
WHEN_KEYS = {"any_rule", "max_severity_at_most"} | GUARD_WHEN_KEYS
LIST_KEYS = {"any_rule", "tool", "tool_class", "role", "dest_class", "path_class"}
ALLOW_REASON = "No suspicious behaviour in the tested run (limited evidence)."
LABELS = {"ALLOW": "allowed", "ESCALATE": "needs human review (denied)", "ASK": "needs your approval",
          "BLOCK": "blocked"}


class PolicyError(Exception):
    pass


INDETERMINATE_RULES = {"INCOMPLETE_TRACE", "EVIDENCE_UNAVAILABLE"}


class Decision(BaseModel):
    decision: str
    matched_rules: list[str]
    findings: list[Finding]
    confidence: str = "limited"
    reason: str
    error: bool = False  # produced by decide_error: the pipeline itself could not reach a verdict

    @property
    def indeterminate(self) -> bool:
        """Denied because the evidence is missing or incomplete (or the pipeline failed), not because of behaviour."""
        if self.decision == "BLOCK":
            return False
        return self.error or any(f.rule_id in INDETERMINATE_RULES for f in self.findings)

    @property
    def denied(self) -> bool:
        return self.decision != "ALLOW"

    @property
    def label(self) -> str:
        return LABELS[self.decision]

    @property
    def exit_code(self) -> int:
        return {"ALLOW": 0, "BLOCK": 2, "ESCALATE": 3, "ASK": 3}[self.decision]


def load_policy(path: Path | None = None) -> dict:
    try:
        data = yaml.safe_load((path or config.ROOT / "policies" / "default.yaml").read_text())
    except Exception as e:
        raise PolicyError(f"cannot load policy: {e}") from e
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("rules"), list):
        raise PolicyError("policy must be a mapping with version: 1 and a rules list")
    for r in data["rules"]:
        if not isinstance(r, dict) or {"id", "when", "decision"} - set(r):
            raise PolicyError(f"malformed rule: {r!r}")
        if r["decision"] not in STRICTNESS:
            raise PolicyError(f"rule {r['id']}: unknown decision {r['decision']!r}")
        when = r["when"]
        if not isinstance(when, dict) or not when or set(when) - WHEN_KEYS:
            raise PolicyError(f"rule {r['id']}: unsupported 'when' {when!r}")
        if "max_severity_at_most" in when and when["max_severity_at_most"] not in SEVERITY_ORDER:
            raise PolicyError(f"rule {r['id']}: unknown severity {when['max_severity_at_most']!r}")
        for k in LIST_KEYS & set(when):
            if not isinstance(when[k], list) or not all(isinstance(x, str) for x in when[k]):
                raise PolicyError(f"rule {r['id']}: '{k}' must be a list of strings")
        if "taint_at_least" in when and when["taint_at_least"] not in TAINT_ORDER:
            raise PolicyError(f"rule {r['id']}: unknown taint {when['taint_at_least']!r}")
        if "min_score" in when:
            ms = when["min_score"]
            if not isinstance(ms, (int, float)) or not 0 <= ms <= 1 or "any_rule" not in when:
                raise PolicyError(f"rule {r['id']}: min_score must be 0..1 and used with any_rule")
    return data


def _matches(when: dict, findings: list[Finding], ctx: dict | None = None) -> bool:
    if GUARD_WHEN_KEYS & set(when) - {"min_score"} and ctx is None:
        return False  # a tool-call rule never matches a package scan
    ctx = ctx or {}
    ok = True
    if "any_rule" in when:
        wanted = set(when["any_rule"])
        floor = when.get("min_score", 0.0)
        ok &= any(f.rule_id in wanted and f.score >= floor for f in findings)
    if "max_severity_at_most" in when:
        top = max((SEVERITY_ORDER[f.severity] for f in findings), default=0)
        ok &= top <= SEVERITY_ORDER[when["max_severity_at_most"]]
    if "tool" in when:
        ok &= any(fnmatch(ctx.get("tool") or "", pat) for pat in when["tool"])
    for key in ("tool_class", "role", "dest_class", "path_class"):
        if key in when:
            ok &= ctx.get(key) in when[key]
    if "taint_at_least" in when:
        ok &= TAINT_ORDER.get(ctx.get("taint") or "trusted", 0) >= TAINT_ORDER[when["taint_at_least"]]
    return ok


def decide(findings: list[Finding], policy: dict | None = None, policy_path: Path | None = None) -> Decision:
    """Never raises: any internal error becomes a BLOCK."""
    try:
        pol = policy or load_policy(policy_path)
        matched = [(r["id"], r["decision"]) for r in pol["rules"] if _matches(r["when"], findings)]
        if not matched:  # nothing vouched for this run
            return Decision(decision="ESCALATE", matched_rules=[], findings=findings,
                            reason="No policy rule matched; needs human review (fail closed).")
        final = max((d for _, d in matched), key=STRICTNESS.get)
        ids = [i for i, _ in matched]
        if final == "ALLOW":
            reason = ALLOW_REASON
        else:
            reasons = "; ".join(f"{f.rule_id}: {f.message}" for f in findings
                                if SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["medium"])
            reason = f"{LABELS[final].capitalize()}. {reasons}" if reasons else f"{LABELS[final].capitalize()}."
        return Decision(decision=final, matched_rules=ids, findings=findings, reason=reason)
    except Exception as e:
        return Decision(decision="BLOCK", matched_rules=[], findings=list(findings) if isinstance(findings, list) else [],
                        reason=f"Policy evaluation failed ({type(e).__name__}: {e}); blocked (fail closed).")


def decide_error(message: str, block: bool = False) -> Decision:
    """Pipeline-level failure (fetch error, doctor failure, ...): never ALLOW."""
    d = "BLOCK" if block else "ESCALATE"
    return Decision(decision=d, matched_rules=[], findings=[], error=True,
                    reason=f"{message}; {LABELS[d]} (fail closed).")


def _reason(final: str, findings: list[Finding]) -> str:
    reasons = "; ".join(f"{f.rule_id}: {f.message}" for f in findings
                        if SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["medium"])
    return f"{LABELS[final].capitalize()}. {reasons}" if reasons else f"{LABELS[final].capitalize()}."


def decide_call(findings: list[Finding], ctx: dict, policy: dict | None = None,
                policy_path: Path | None = None) -> Decision:
    """AI tool-call verdict: ALLOW, ASK or BLOCK. Never raises; nothing matched -> ASK; any error -> BLOCK.
    ctx: tool, tool_class, role, taint, dest_class, path_class."""
    try:
        pol = policy or load_policy(policy_path or config.GUARD_POLICY)
        matched = [(r["id"], "ASK" if r["decision"] == "ESCALATE" else r["decision"])
                   for r in pol["rules"] if _matches(r["when"], findings, ctx)]
        if not matched:
            return Decision(decision="ASK", matched_rules=[], findings=findings,
                            reason="No policy rule matched this tool call; asking a human (fail closed).")
        final = max((d for _, d in matched), key=STRICTNESS.get)
        reason = "Allowed: no risky signal for this tool call." if final == "ALLOW" else _reason(final, findings)
        if final != "ALLOW" and reason.endswith(f"{LABELS[final].capitalize()}."):
            reason += " Matched: " + ", ".join(i for i, d in matched if d == final)
        return Decision(decision=final, matched_rules=[i for i, _ in matched], findings=findings, reason=reason)
    except Exception as e:
        return Decision(decision="BLOCK", matched_rules=[], findings=list(findings) if isinstance(findings, list) else [],
                        error=True, reason=f"Policy evaluation failed ({type(e).__name__}: {e}); blocked (fail closed).")


def lint_policy(path: Path) -> list[str]:
    """Human-readable problems with a policy file ([] when clean)."""
    try:
        data = load_policy(path)
    except PolicyError as e:
        return [str(e)]
    problems = []
    ids = [r["id"] for r in data["rules"]]
    problems += [f"duplicate rule id {i!r}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    for name, role in (data.get("roles") or {}).items():
        if not isinstance(role, dict) or not isinstance(role.get("tools"), list):
            problems.append(f"role {name!r}: needs a 'tools' list")
    if data.get("roles") is not None and not any(r["decision"] == "ALLOW" for r in data["rules"]):
        problems.append("no ALLOW rule: every tool call would need approval")
    return problems
