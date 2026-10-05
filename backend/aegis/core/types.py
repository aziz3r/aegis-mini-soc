"""Shared data types. Everything upstream (pcap, live capture, lab generator)
normalises into `Packet`; everything downstream consumes `Flow` / `Verdict`."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

Proto = Literal["tcp", "udp", "icmp", "other"]

# TCP flag bits, as scapy exposes them.
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@dataclass(slots=True)
class Packet:
    """One observed packet, protocol-normalised."""

    ts: float
    src: str
    dst: str
    proto: Proto
    sport: int
    dport: int
    size: int                 # full frame size in bytes
    flags: int = 0            # TCP flags bitfield, 0 for non-TCP
    payload: bytes = b""      # first N payload bytes (truncated by the source)
    label: str = "BENIGN"     # ground truth; only set by labelled sources

    @property
    def payload_len(self) -> int:
        return len(self.payload)


@dataclass(slots=True)
class FlowKey:
    """Bidirectional 5-tuple. `src`/`sport` is always the initiator side."""

    src: str
    dst: str
    sport: int
    dport: int
    proto: Proto

    def as_tuple(self) -> tuple[str, str, int, int, str]:
        return (self.src, self.dst, self.sport, self.dport, self.proto)

    def canonical(self) -> tuple[str, str, int, int, str]:
        """Direction-agnostic identity, so A->B and B->A map to one flow."""
        a, b = (self.src, self.sport), (self.dst, self.dport)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo[0], hi[0], lo[1], hi[1], self.proto)

    def __str__(self) -> str:
        return f"{self.src}:{self.sport} -> {self.dst}:{self.dport}/{self.proto}"


@dataclass(slots=True)
class Flow:
    """An exported flow record: the unit the ML model scores."""

    key: FlowKey
    start_ts: float
    end_ts: float
    features: dict[str, float]
    label: str = "BENIGN"           # ground truth when the source provides it
    #: when the flow left the table. Detection cannot happen before this, so it
    #: is the only honest clock for a latency measurement - `end_ts` is the last
    #: packet, which is up to one idle timeout earlier.
    export_ts: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    @property
    def duration(self) -> float:
        return max(self.end_ts - self.start_ts, 0.0)

    @property
    def packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes


@dataclass(slots=True)
class Contribution:
    """One line of the 'why was this flagged' explanation."""

    feature: str
    value: float
    baseline: float
    impact: float          # share of the anomaly score attributable to this feature
    direction: str         # "above" | "below" baseline

    def as_dict(self) -> dict[str, object]:
        return {
            "feature": self.feature,
            "value": round(self.value, 4),
            "baseline": round(self.baseline, 4),
            "impact": round(self.impact, 4),
            "direction": self.direction,
        }


@dataclass(slots=True)
class Verdict:
    """Engine output for one flow."""

    flow: Flow
    score: float                      # calibrated anomaly probability, 0..1
    threshold: float                  # the adaptive threshold it was compared to
    is_alert: bool
    family: str = "UNKNOWN"           # supervised label, or UNKNOWN below confidence
    family_confidence: float = 0.0
    contributions: list[Contribution] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if not self.is_alert:
            return "INFO"
        margin = self.score - self.threshold
        if self.score >= 0.92 or margin >= 0.25:
            return "CRITICAL"
        if margin >= 0.10:
            return "HIGH"
        return "MEDIUM"


def shannon_entropy(data: bytes) -> float:
    """Normalised Shannon entropy (0..1) of a byte string.

    High entropy on an unusual port is a strong signal for tunnelling or
    encrypted exfiltration; near-zero entropy means padding or plain text.
    """
    if not data:
        return 0.0
    n = len(data)
    inv = 1.0 / n
    log2 = math.log2
    # Counter does the tallying in C and yields only the symbols that occur.
    entropy = -sum((c := count * inv) * log2(c) for count in Counter(data).values())
    return entropy / 8.0
