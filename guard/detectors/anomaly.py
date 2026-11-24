"""Per-session behaviour: a secret read (or attempted read) followed by an outbound send."""
from shadowrun.models import Finding

WINDOW = 6


def scan(session, tool_class: str) -> list[Finding]:
    if tool_class != "external_send":
        return []
    recent = session.history[-WINDOW:]
    if any(h.get("path_class") == "secret" or h.get("tool_class") == "sensitive_read" for h in recent):
        return [Finding(rule_id="ANOMALY_SECRET_THEN_SEND", severity="high", score=0.85, detector="anomaly",
                        message=f"Outbound send right after a secrets file was accessed (last {WINDOW} calls)",
                        evidence={"window": WINDOW})]
    return []
