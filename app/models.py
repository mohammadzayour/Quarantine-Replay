"""Typed request shapes. Everything arriving here is untrusted input."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class QuarantineArgs(BaseModel):
    # Unknown fields are tolerated so they can be recorded and visibly ignored
    # (e.g. a model adding "approved_by"). No backend ever reads them.
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    endpoint_id: str = Field(min_length=1, max_length=128)
    incident_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=1000)

    def ignored_fields(self) -> list[str]:
        return sorted(str(k)[:60] for k in (self.model_extra or {}))[:20]


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: Literal["quarantine_endpoint"]
    arguments: QuarantineArgs


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["fixture", "live"] = "fixture"
    scenario: Literal["poisoned", "clean"] = "poisoned"


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keep_live_history: bool = False


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_id: str = Field(min_length=1, max_length=64)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str = Field(min_length=1, max_length=64)
    action: Literal["quarantine_endpoint"]
    endpoint: str = Field(min_length=1, max_length=128)
