"""Request and response models for the HTTP API."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

Status = Literal["NEW", "ACK", "INVESTIGATING", "CLOSED"]
Judgement = Literal["TP", "FP", "BENIGN"]


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    expires_in_minutes: int


class IncidentPatch(BaseModel):
    status: Status | None = None
    assignee: str | None = Field(default=None, max_length=64)
    verdict: Judgement | None = None
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("assignee", "note")
    @classmethod
    def _blank_to_none(cls, v: str | None) -> str | None:
        return v.strip() or None if isinstance(v, str) else v


class BulkAction(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    status: Status | None = None
    assignee: str | None = None
    verdict: Judgement | None = None


class StartLab(BaseModel):
    source: Literal["lab"] = "lab"
    duration: float = Field(default=3600.0, gt=0, le=86_400)
    speed: float = Field(default=1.0, gt=0, le=1000)
    seed: int | None = None
    density: float = Field(default=1.0, gt=0, le=10)
    stealth_ratio: float = Field(default=0.25, ge=0, le=1)


class StartPcap(BaseModel):
    source: Literal["pcap"] = "pcap"
    file: str
    speed: float = Field(default=10.0, ge=0, le=1000)


class StartLive(BaseModel):
    source: Literal["live"] = "live"
    iface: str = Field(min_length=1, max_length=32)
    bpf: str = Field(default="ip", max_length=256)


class AssetIn(BaseModel):
    cidr: str
    name: str = Field(max_length=64)
    criticality: int = Field(default=3, ge=1, le=5)
    tags: list[str] = Field(default_factory=list)


class AssetsIn(BaseModel):
    entries: list[AssetIn] = Field(max_length=500)


class DetectionSettingsIn(BaseModel):
    base_threshold: float = Field(ge=0.5, le=0.9999)
    min_threshold: float = Field(ge=0.5, le=0.9999)
    max_threshold: float = Field(ge=0.5, le=0.99999)
    host_quantile: float = Field(ge=0.5, le=0.9999)
    dedup_window: float = Field(ge=5, le=3600)
    supervised_min_confidence: float = Field(ge=0.0, le=1.0)
