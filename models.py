from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    count: int
    source_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    sample_lines: list[str] = Field(default_factory=list)


class TimeRange(BaseModel):
    start: str | None = None
    end: str | None = None


class LogAnalysisResponse(BaseModel):
    log_type: str
    total_lines: int
    parsed_lines: int
    time_range: TimeRange
    findings: list[Finding]
    summary: dict
