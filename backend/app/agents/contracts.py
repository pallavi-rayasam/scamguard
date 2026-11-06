from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    source: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_level: Literal["verified", "heuristic", "llm_inferred"]
    detail: str


class AgentResult(BaseModel):
    status: Literal["completed", "skipped", "failed", "timed_out", "unavailable"]
    findings: list[dict] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None
