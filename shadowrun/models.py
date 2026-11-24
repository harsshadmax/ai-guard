from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Finding(BaseModel):
    rule_id: str
    severity: str
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    score: float = 1.0            # 0..1 confidence from the detector that produced it
    detector: str = "sandbox"     # which detector produced it (sandbox = the pip deep scan)
    span: dict | None = None      # {"source_id", "start", "end", "text"}: exact text to highlight in the UI


@dataclass
class Event:
    ts: float
    pid: int | None
    syscall: str
    args: str
    ret: str
    kind: str  # FILE_OPEN | FILE_WRITE | NET_CONNECT | PROC_EXEC
    path: str | None = None
    flags: list[str] = field(default_factory=list)
    family: str | None = None
    addr: str | None = None
    port: int | None = None
    argv: list[str] = field(default_factory=list)
    raw: str = ""
