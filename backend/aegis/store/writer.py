"""Persistence of live pipeline output.

Writes are batched per pipeline tick. Under a flood the engine can produce
thousands of alerts a second, and committing each one separately would make the
database the bottleneck in a system whose whole job is to keep up with a network.

Incidents are upserted (one row per correlated group, its occurrence counter
rising), while alerts are appended up to a per-incident cap: keeping the ten
thousandth identical SYN of a flood has no investigative value and would grow the
database without bound. The occurrence counter still tells the full story.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select, update

from aegis.config import settings
from aegis.core.correlate import IncidentEvent, LiveIncident
from aegis.core.mitre import info as mitre_info
from aegis.store.db import Alert, AuditEntry, Bucket, Host, Incident, session_scope


@dataclass
class HostDelta:
    """Counters accumulated for one host between two flushes."""

    flows_out: int = 0
    flows_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    alerts: int = 0
    score_sum: float = 0.0
    score_n: int = 0
    threshold: float = 0.0
    calibrated: bool = False
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BucketDelta:
    ts: datetime
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    alerts: int = 0
    score_sum: float = 0.0
    score_max: float = 0.0
    threshold_sum: float = 0.0

    @property
    def score_mean(self) -> float:
        return self.score_sum / max(self.flows, 1)

    @property
    def threshold_mean(self) -> float:
        return self.threshold_sum / max(self.flows, 1)

    def as_point(self) -> dict[str, float | str | int]:
        return {
            "ts": self.ts.isoformat(),
            "flows": self.flows,
            "packets": self.packets,
            "bytes": self.bytes,
            "alerts": self.alerts,
            "score_mean": round(self.score_mean, 4),
            "score_max": round(self.score_max, 4),
            "threshold": round(self.threshold_mean, 4),
        }


class Writer:
    """Batch writer. One instance per pipeline."""

    def __init__(self) -> None:
        self.incidents_written = 0
        self.alerts_written = 0
        self.alerts_dropped = 0

    # -- incidents ------------------------------------------------------------

    def flush_incidents(self, events: list[IncidentEvent]) -> list[dict]:
        """Upsert every touched incident, append its pending alerts.

        Returns one broadcast payload per touched incident (newest state).
        """
        if not events:
            return []
        touched: dict[int, LiveIncident] = {}
        new_flags: dict[int, bool] = {}
        for ev in events:
            key = id(ev.incident)
            touched[key] = ev.incident
            new_flags[key] = new_flags.get(key, False) or ev.is_new

        payloads: list[dict] = []
        with session_scope() as sess:
            for key, inc in touched.items():
                row = sess.get(Incident, inc.db_id) if inc.db_id else None
                if row is None:
                    row = Incident(dedup_key=inc.dedup_key, family=inc.family,
                                   status="NEW", occurrences=0, total_bytes=0, total_packets=0,
                                   contributions=[])
                    sess.add(row)
                    self.incidents_written += 1
                self._apply(row, inc)
                sess.flush()
                inc.db_id = row.id

                pending, inc.pending = inc.pending, []
                existing = sess.scalar(
                    select(Alert.id).where(Alert.incident_id == row.id).limit(1)
                )
                count = sess.query(Alert).filter(Alert.incident_id == row.id).count() if existing else 0
                for verdict in pending:
                    if count >= settings.incident_max_alerts:
                        self.alerts_dropped += 1
                        continue
                    sess.add(_alert_row(row.id, verdict))
                    count += 1
                    self.alerts_written += 1
                payloads.append(incident_payload(row, is_new=new_flags[key]))
        return payloads

    @staticmethod
    def _apply(row: Incident, inc: LiveIncident) -> None:
        mitre = mitre_info(inc.family)
        row.family = inc.family
        row.src = inc.src
        row.dst = inc.dst
        row.dport = inc.dport
        row.proto = inc.proto
        row.first_seen = inc.first_seen
        row.last_seen = inc.last_seen
        row.occurrences = inc.occurrences
        row.score_max = inc.score_max
        row.score_mean = inc.score_mean
        row.threshold = inc.threshold
        row.confidence = inc.confidence
        row.severity = inc.severity
        row.priority = inc.priority
        row.criticality = inc.criticality
        row.asset_name = inc.asset_name
        row.mitre_technique = mitre.technique
        row.mitre_tactic = mitre.tactic
        row.total_bytes = inc.total_bytes
        row.total_packets = inc.total_packets
        row.distinct_dports = len(inc.dports)
        row.distinct_peers = len(inc.peers)
        if inc.contributions:
            row.contributions = inc.contributions
        if row.status is None:
            row.status = "NEW"

    # -- rollups --------------------------------------------------------------

    def flush_bucket(self, bucket: BucketDelta) -> None:
        with session_scope() as sess:
            sess.add(Bucket(
                ts=bucket.ts, flows=bucket.flows, packets=bucket.packets, bytes=bucket.bytes,
                alerts=bucket.alerts, score_mean=bucket.score_mean,
                score_max=bucket.score_max, threshold_mean=bucket.threshold_mean,
            ))

    def flush_hosts(self, deltas: dict[str, HostDelta], assets) -> None:
        if not deltas:
            return
        with session_scope() as sess:
            for ip, d in deltas.items():
                row = sess.get(Host, ip)
                if row is None:
                    asset = assets.lookup(ip)
                    # Column defaults are applied by the database at INSERT, so a
                    # freshly constructed row still holds None in memory - every
                    # counter is initialised explicitly rather than accumulated
                    # onto None.
                    row = Host(
                        ip=ip, asset_name=asset.name, criticality=asset.criticality,
                        first_seen=d.last_seen, last_seen=d.last_seen,
                        flows_out=0, flows_in=0, bytes_out=0, bytes_in=0,
                        alerts=0, score_mean=0.0, threshold=0.0, calibrated=False,
                    )
                    sess.add(row)
                row.last_seen = d.last_seen
                row.flows_out = (row.flows_out or 0) + d.flows_out
                row.flows_in = (row.flows_in or 0) + d.flows_in
                row.bytes_out = (row.bytes_out or 0) + d.bytes_out
                row.bytes_in = (row.bytes_in or 0) + d.bytes_in
                row.alerts = (row.alerts or 0) + d.alerts
                if d.score_n:
                    # running mean over the host's whole lifetime
                    total = row.flows_out + row.flows_in
                    prev_n = max(total - d.score_n, 0)
                    row.score_mean = ((row.score_mean or 0.0) * prev_n + d.score_sum) / max(total, 1)
                if d.threshold:
                    row.threshold = d.threshold
                    row.calibrated = d.calibrated

    # -- audit ----------------------------------------------------------------

    @staticmethod
    def audit(actor: str, action: str, target: str = "", detail: dict | None = None) -> None:
        with session_scope() as sess:
            sess.add(AuditEntry(actor=actor, action=action, target=target, detail=detail or {}))


def _alert_row(incident_id: int, verdict) -> Alert:
    flow = verdict.flow
    return Alert(
        incident_id=incident_id,
        ts=datetime.now(timezone.utc),
        flow_start=flow.start_ts,
        flow_end=flow.end_ts,
        src=flow.key.src, sport=flow.key.sport,
        dst=flow.key.dst, dport=flow.key.dport, proto=flow.key.proto,
        score=verdict.score, threshold=verdict.threshold,
        family=verdict.family, confidence=verdict.family_confidence,
        severity=verdict.severity,
        packets=flow.packets, bytes=flow.bytes, duration=flow.duration,
        truth=flow.label if flow.label else None,
        contributions=[c.as_dict() for c in verdict.contributions],
    )


def incident_payload(row: Incident, is_new: bool = False) -> dict:
    mitre = mitre_info(row.family)
    return {
        "id": row.id,
        "family": row.family,
        "family_title": mitre.title,
        "src": row.src,
        "dst": row.dst,
        "dport": row.dport,
        "proto": row.proto,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "occurrences": row.occurrences,
        "score_max": round(row.score_max, 4),
        "score_mean": round(row.score_mean, 4),
        "threshold": round(row.threshold, 4),
        "confidence": round(row.confidence, 4),
        "severity": row.severity,
        "priority": row.priority,
        "criticality": row.criticality,
        "asset_name": row.asset_name,
        "status": row.status,
        "assignee": row.assignee,
        "verdict": row.verdict,
        "note": row.note,
        "mitre_technique": row.mitre_technique,
        "mitre_tactic": row.mitre_tactic,
        "contributions": row.contributions or [],
        "total_bytes": row.total_bytes,
        "total_packets": row.total_packets,
        "distinct_dports": row.distinct_dports,
        "distinct_peers": row.distinct_peers,
        "is_new": is_new,
    }
