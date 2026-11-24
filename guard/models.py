"""Data types for the AI tool guard."""
import threading
import time
import uuid
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from shadowrun.models import Finding


class Trust(str, Enum):
    trusted = "trusted"      # the user's own prompt, the system
    internal = "internal"    # company files and colleagues
    untrusted = "untrusted"  # the web, inbound mail from outside, third-party documents, plugin output


TRUST_RANK = {Trust.trusted: 0, Trust.internal: 1, Trust.untrusted: 2}


class ToolClass(str, Enum):
    read = "read"
    sensitive_read = "sensitive_read"
    write = "write"
    external_send = "external_send"
    destructive = "destructive"
    exec = "exec"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ToolSpec(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    description: str
    tool_class: ToolClass
    server: str = "builtin"
    input_schema: dict = Field(default_factory=dict)
    executor: Callable[..., Any] | None = Field(default=None, exclude=True)


class ToolCall(BaseModel):
    id: str = Field(default_factory=lambda: new_id("call"))
    session_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    ts: float = Field(default_factory=time.time)


class Source(BaseModel):
    id: str = Field(default_factory=lambda: new_id("src"))
    session_id: str
    origin: str                 # e.g. "file:docs/external/client_feedback.html", "url:https://...", "tool:get_weather"
    trust: Trust
    text: str                   # full normalised text the model saw (visible + hidden)
    hidden_text: str = ""       # what a human reader would NOT see
    sha256: str = ""
    findings: list[Finding] = Field(default_factory=list)


class Session(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ses"))
    user_id: str = "demo-user"
    role: str = "analyst"
    agent_id: str = "agent"
    guard_on: bool = True
    task: str = ""
    taint: Trust = Trust.trusted
    sources: list[Source] = Field(default_factory=list)
    history: list[dict] = Field(default_factory=list)     # [{tool, tool_class, path_class, decision, ts}]
    call_times: list[float] = Field(default_factory=list)
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def raise_taint(self, trust: Trust) -> bool:
        if TRUST_RANK[trust] > TRUST_RANK[self.taint]:
            self.taint = trust
            return True
        return False

    @property
    def untrusted_sources(self) -> list[Source]:
        return [s for s in self.sources if s.trust == Trust.untrusted]


class Verdict(BaseModel):
    call_id: str
    session_id: str
    tool: str
    decision: str                          # ALLOW | ASK | BLOCK | UNGUARDED
    reason: str
    explanation: str = ""                  # plain-English text for the human
    matched_rules: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)        # pre-execution findings
    post_findings: list[Finding] = Field(default_factory=list)   # findings on the tool result
    latency_ms: float = 0.0                # guard overhead until the decision
    taint: str = "trusted"
    tool_class: str = ""
    source_ids: list[str] = Field(default_factory=list)
    executed: bool = False
    result: Any = None
    redactions: list[dict] = Field(default_factory=list)
    approval_id: str | None = None

    @property
    def rule_ids(self) -> set[str]:
        return {f.rule_id for f in self.findings + self.post_findings}


class Store:
    """In-memory session registry (the DB keeps the durable copy for the dashboard)."""

    def __init__(self):
        self.lock = threading.RLock()
        self.sessions: dict[str, Session] = {}

    def get(self, sid: str) -> Session | None:
        with self.lock:
            return self.sessions.get(sid)

    def put(self, s: Session) -> None:
        with self.lock:
            self.sessions[s.id] = s


STORE = Store()
