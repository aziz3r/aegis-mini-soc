"""The detection engine: packets in, verdicts out.

This is the only place where flow assembly, scoring, thresholding and
explanation meet. Both the live pipeline and the offline benchmark drive the same
class with the same code path - that is deliberate, so a benchmark number cannot
describe a system different from the one that runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from aegis.config import settings
from aegis.core.assets import AssetRegistry
from aegis.core.flows import FlowTable
from aegis.core.types import Flow, Packet, Verdict
from aegis.ml.dataset import vectorize_many
from aegis.ml.model import DetectionModel
from aegis.ml.threshold import AdaptiveThreshold

#: Occlusion attribution costs one batched scoring call per explained alert. A
#: flood can raise hundreds of alerts per second, and explaining each one would
#: dominate the loop for no benefit: they are merged into a single incident that
#: needs a single explanation. The budget caps the work per batch; the incident
#: keeps the explanation from its highest-scoring alert.
EXPLAIN_BUDGET = 6


@dataclass
class EngineStats:
    packets: int = 0
    flows: int = 0
    alerts: int = 0
    suppressed: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    score_sum: float = 0.0
    score_max: float = 0.0
    by_family: dict[str, int] = field(default_factory=dict)

    @property
    def score_mean(self) -> float:
        return self.score_sum / max(self.flows, 1)

    @property
    def span(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    @property
    def alerts_per_hour(self) -> float:
        return self.alerts / (self.span / 3600.0) if self.span > 0 else 0.0

    def as_dict(self) -> dict[str, float | int | dict]:
        return {
            "packets": self.packets,
            "flows": self.flows,
            "alerts": self.alerts,
            "bytes": self.bytes,
            "span": round(self.span, 2),
            "score_mean": round(self.score_mean, 4),
            "score_max": round(self.score_max, 4),
            "alerts_per_hour": round(self.alerts_per_hour, 2),
            "suppressed": self.suppressed,
            "by_family": dict(self.by_family),
        }


class Engine:
    """Stateful detector. Not thread-safe; run one per ingest worker."""

    def __init__(
        self,
        model: DetectionModel,
        assets: AssetRegistry | None = None,
        thresholds: AdaptiveThreshold | None = None,
        explain: bool = True,
    ) -> None:
        if not model.is_ready:
            raise ValueError("model is not trained; run `aegis train` first")
        self.model = model
        self.assets = assets or AssetRegistry()
        self.thresholds = thresholds or AdaptiveThreshold()
        self.table = FlowTable()
        self.stats = EngineStats()
        self.explain = explain

    # -- ingestion ------------------------------------------------------------

    def feed_packet(self, pkt: Packet) -> list[Verdict]:
        self.stats.packets += 1
        self.stats.bytes += pkt.size
        if self.stats.first_ts == 0.0:
            self.stats.first_ts = pkt.ts
        self.stats.last_ts = max(self.stats.last_ts, pkt.ts)
        return self.score_flows(self.table.add(pkt))

    def feed_packets(self, packets) -> list[Verdict]:
        """Batch ingestion: one scoring call per batch instead of per flow."""
        flows: list[Flow] = []
        for pkt in packets:
            self.stats.packets += 1
            self.stats.bytes += pkt.size
            if self.stats.first_ts == 0.0:
                self.stats.first_ts = pkt.ts
            self.stats.last_ts = max(self.stats.last_ts, pkt.ts)
            flows.extend(self.table.add(pkt))
        return self.score_flows(flows)

    def finish(self) -> list[Verdict]:
        """Flush the flow table at end of capture and score what comes out."""
        return self.score_flows(self.table.flush())

    # -- scoring --------------------------------------------------------------

    def score_flows(self, flows: list[Flow]) -> list[Verdict]:
        if not flows:
            return []
        X = vectorize_many(flows)
        scores = self.model.score(X)
        families, confidences = self.model.classify(X)

        verdicts: list[Verdict] = []
        for i, flow in enumerate(flows):
            score = float(scores[i])
            host = flow.key.src
            # Query the threshold *before* feeding this score into the baseline,
            # so a flow can never influence the threshold it is judged against.
            threshold = self.thresholds.threshold(host)
            raw_family, confidence = str(families[i]), float(confidences[i])
            is_alert = score >= threshold
            suppressed = False
            if (
                is_alert
                and raw_family == "BENIGN"
                and confidence >= settings.benign_suppress_confidence
                and score < settings.alert_override_score
            ):
                # The cascade: stage A flagged it, stage B recognises it as normal
                # traffic and is confident. Below the override score, trust the
                # classifier - this is what keeps the alert queue workable.
                is_alert = False
                suppressed = True
            self.thresholds.observe(host, score, alerted=is_alert)

            family = raw_family if is_alert else "BENIGN"
            verdicts.append(Verdict(
                flow=flow,
                score=score,
                threshold=threshold,
                is_alert=is_alert,
                family=family,
                family_confidence=confidence,
            ))

            self.stats.flows += 1
            self.stats.score_sum += score
            self.stats.score_max = max(self.stats.score_max, score)
            if suppressed:
                self.stats.suppressed += 1
            if is_alert:
                self.stats.alerts += 1
                self.stats.by_family[family] = self.stats.by_family.get(family, 0) + 1

        if self.explain:
            self._explain_top(verdicts, X)
        return verdicts

    def _explain_top(self, verdicts: list[Verdict], X: np.ndarray) -> None:
        alerting = [i for i, v in enumerate(verdicts) if v.is_alert]
        if not alerting:
            return
        alerting.sort(key=lambda i: -verdicts[i].score)
        for i in alerting[:EXPLAIN_BUDGET]:
            verdicts[i].contributions = self.model.explain(X[i])

    # -- maintenance ----------------------------------------------------------

    def housekeeping(self, now: float) -> list[Verdict]:
        """Expire idle flows on a timer, so a quiet host still reports."""
        self.table.hosts.prune(now)
        self.table.peers.prune(now)
        return self.score_flows(self.table.expire(now))
