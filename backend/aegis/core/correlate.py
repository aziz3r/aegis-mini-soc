"""Alert correlation: alerts in, incidents out.

A SYN flood produces thousands of alerting flows per minute. Showing them one by
one is how a SOC drowns - the failure mode has a name, alert fatigue, and it is
the reason analysts stop reading dashboards.

Correlation collapses them into one incident with an occurrence count, and
chooses its grouping key per family, because the shape of an attack determines
what "the same event" means:

  * one-to-many (a scan: one source, many ports/hosts)  -> group on the source;
  * many-to-one (a flood: many spoofed sources, one victim) -> group on the victim;
  * one-to-one (brute force, beacon, exfiltration)      -> group on the pair.

Severity is then not the score. It is the score's margin over the host's own
threshold, weighted by what the targeted asset is worth and how confident the
classifier is - so a scan against the database server outranks a louder scan
against a printer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from aegis.config import settings
from aegis.core.assets import AssetRegistry
from aegis.core.mitre import info as mitre_info
from aegis.core.types import Verdict

#: Families whose natural shape is many sources against one victim.
VICTIM_GROUPED = frozenset({"DOS_FLOOD", "SLOWLORIS"})
#: Families whose natural shape is one source against many targets.
SOURCE_GROUPED = frozenset({"PORT_SCAN", "NET_SCAN"})

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def dedup_key(verdict: Verdict) -> str:
    key = verdict.flow.key
    family = verdict.family
    if family in VICTIM_GROUPED:
        return f"{family}|*|{key.dst}"
    if family in SOURCE_GROUPED:
        return f"{family}|{key.src}|*"
    return f"{family}|{key.src}|{key.dst}"


@dataclass(slots=True)
class LiveIncident:
    """An incident while it is still being aggregated in memory."""

    dedup_key: str
    family: str
    src: str
    dst: str
    dport: int
    proto: str
    first_seen: datetime
    last_seen: datetime
    occurrences: int = 1
    score_max: float = 0.0
    score_sum: float = 0.0
    threshold: float = 0.0
    confidence: float = 0.0
    criticality: int = 3
    asset_name: str = ""
    contributions: list[dict] = field(default_factory=list)
    total_bytes: int = 0
    total_packets: int = 0
    peers: set[str] = field(default_factory=set)
    dports: set[int] = field(default_factory=set)
    db_id: int | None = None
    #: alerts not yet written to the database
    pending: list[Verdict] = field(default_factory=list)
    #: ground-truth tally, only populated by labelled sources (benchmark mode)
    truth: dict[str, int] = field(default_factory=dict)

    @property
    def score_mean(self) -> float:
        return self.score_sum / max(self.occurrences, 1)

    @property
    def margin(self) -> float:
        span = max(1.0 - self.threshold, 1e-6)
        return max(0.0, min(1.0, (self.score_max - self.threshold) / span))

    @property
    def priority(self) -> int:
        """0-100. Blends anomaly margin, asset value and classifier confidence."""
        volume_boost = min(self.occurrences / 200.0, 1.0) * 0.08
        return int(round(100 * min(1.0, (
            0.50 * self.margin
            + 0.30 * (self.criticality / 5.0)
            + 0.12 * self.confidence
            + volume_boost
        ))))

    @property
    def severity(self) -> str:
        p = self.priority
        if p >= 75:
            return "CRITICAL"
        if p >= 58:
            return "HIGH"
        if p >= 38:
            return "MEDIUM"
        return "LOW"


@dataclass(slots=True)
class IncidentEvent:
    incident: LiveIncident
    is_new: bool
    verdict: Verdict


class Correlator:
    """Groups verdicts into incidents inside a sliding dedup window."""

    def __init__(self, assets: AssetRegistry | None = None) -> None:
        self.assets = assets or AssetRegistry()
        self._active: dict[str, LiveIncident] = {}
        self.incidents_opened = 0
        self.alerts_merged = 0

    def ingest(self, verdict: Verdict, now: datetime | None = None) -> IncidentEvent:
        now = now or datetime.now(timezone.utc)
        key = dedup_key(verdict)
        flow = verdict.flow
        existing = self._active.get(key)

        if existing is not None and (now - existing.last_seen) <= timedelta(seconds=settings.dedup_window):
            inc = existing
            inc.last_seen = now
            inc.occurrences += 1
            inc.score_sum += verdict.score
            is_new = False
            self.alerts_merged += 1
            if verdict.score > inc.score_max:
                inc.score_max = verdict.score
                inc.threshold = verdict.threshold
                inc.confidence = max(inc.confidence, verdict.family_confidence)
                if verdict.contributions:
                    inc.contributions = [c.as_dict() for c in verdict.contributions]
        else:
            asset = self.assets.lookup(flow.key.dst)
            family_crit = mitre_info(verdict.family).default_criticality
            inc = LiveIncident(
                dedup_key=key,
                family=verdict.family,
                src=flow.key.src,
                dst=flow.key.dst,
                dport=flow.key.dport,
                proto=flow.key.proto,
                first_seen=now,
                last_seen=now,
                score_max=verdict.score,
                score_sum=verdict.score,
                threshold=verdict.threshold,
                confidence=verdict.family_confidence,
                criticality=max(asset.criticality, family_crit),
                asset_name=asset.name,
                contributions=[c.as_dict() for c in verdict.contributions],
            )
            self._active[key] = inc
            self.incidents_opened += 1
            is_new = True

        inc.total_bytes += flow.bytes
        inc.total_packets += flow.packets
        inc.peers.add(flow.key.src if verdict.family in VICTIM_GROUPED else flow.key.dst)
        inc.dports.add(flow.key.dport)
        inc.pending.append(verdict)
        if flow.label:
            inc.truth[flow.label] = inc.truth.get(flow.label, 0) + 1
        return IncidentEvent(incident=inc, is_new=is_new, verdict=verdict)

    def sweep(self, now: datetime | None = None) -> list[LiveIncident]:
        """Retire incidents whose dedup window has elapsed; return them."""
        now = now or datetime.now(timezone.utc)
        cutoff = timedelta(seconds=settings.dedup_window)
        done = [k for k, inc in self._active.items() if (now - inc.last_seen) > cutoff]
        return [self._active.pop(k) for k in done]

    @property
    def active(self) -> list[LiveIncident]:
        return list(self._active.values())
