"""Adaptive alerting threshold.

A single global threshold is the flaw at the heart of the original mock-up. A
backup server that talks to twelve hosts at 3 a.m. and a receptionist's laptop
do not have the same normal, so they cannot share a cut-off.

### Why a quantile and not median + k·MAD

The first implementation here used the textbook robust rule, `median + k·MAD`.
Measured, it destroyed recall: it drove every threshold to the ceiling and recall
fell to 14%. The reason is that stage A scores are **already** the empirical CDF
of benign traffic, so on normal traffic they are near-uniform on [0, 1]: the
median sits at ~0.52 and the MAD at ~0.24, and `0.52 + 4 × 1.4826 × 0.24 ≈ 1.94`
clamps to the maximum for every host. MAD assumes a distribution with a tight
core and rare outliers; a uniform distribution has neither.

The right statistic in a percentile space is a **quantile of the host's own
scores**:

    threshold(host) = clamp( max(base_threshold, quantile(host_scores, q)),
                             min_threshold, max_threshold )

which reads directly as a false-positive budget: "alert on the 1% most unusual
flows for this host, but never below the global floor". A host whose normal is
quiet keeps the global floor; a host whose normal is genuinely odd - a backup
server, a monitoring probe - raises its own bar and stops crying wolf.

Two safeguards:

* only scores that did **not** alert feed the baseline. Otherwise a host under
  sustained attack would normalise its own attack traffic and go quiet: the
  boiling-frog failure, and the way a patient attacker beats naive adaptation.
* the ceiling caps how far a host may raise its bar, so a slow attack that does
  manage to seep into a baseline cannot push that host beyond the reach of
  detection.
"""
from __future__ import annotations

from collections import deque

import numpy as np

from aegis.config import settings

_RECOMPUTE_EVERY = 16


class AdaptiveThreshold:
    """Per-host quantile threshold with a global floor."""

    def __init__(self, window: int = 512) -> None:
        self.window = window
        self._scores: dict[str, deque[float]] = {}
        self._cached: dict[str, float] = {}
        self._since: dict[str, int] = {}
        self.observed = 0

    # -- queries --------------------------------------------------------------

    def threshold(self, host: str) -> float:
        bucket = self._scores.get(host)
        if bucket is None or len(bucket) < settings.baseline_min_samples:
            # Cold start: the global floor *is* the operating point. Deriving a
            # value from other hosts' scores would mix incomparable baselines.
            return settings.base_threshold
        cached = self._cached.get(host)
        return cached if cached is not None else self._recompute(host)

    def baseline_size(self, host: str) -> int:
        return len(self._scores.get(host, ()))

    def is_host_calibrated(self, host: str) -> bool:
        return self.baseline_size(host) >= settings.baseline_min_samples

    # -- updates --------------------------------------------------------------

    def observe(self, host: str, score: float, alerted: bool) -> None:
        """Feed a score into the host baseline. Alerting scores are excluded."""
        if alerted:
            return
        self.observed += 1
        bucket = self._scores.get(host)
        if bucket is None:
            bucket = self._scores[host] = deque(maxlen=self.window)
        bucket.append(score)
        self._since[host] = self._since.get(host, 0) + 1
        if self._since[host] >= _RECOMPUTE_EVERY:
            self._recompute(host)

    def _recompute(self, host: str) -> float:
        bucket = self._scores[host]
        self._since[host] = 0
        if len(bucket) < settings.baseline_min_samples:
            self._cached.pop(host, None)
            return settings.base_threshold
        arr = np.fromiter(bucket, dtype=np.float64, count=len(bucket))
        value = float(np.quantile(arr, settings.host_quantile))
        value = max(value, settings.base_threshold)
        value = min(max(value, settings.min_threshold), settings.max_threshold)
        self._cached[host] = value
        return value

    def prune(self, keep: int = 20_000) -> None:
        """Bound memory on a long run by forgetting the least active hosts."""
        if len(self._scores) <= keep:
            return
        for host in sorted(self._scores, key=lambda h: len(self._scores[h]))[: len(self._scores) - keep]:
            self._scores.pop(host, None)
            self._cached.pop(host, None)
            self._since.pop(host, None)

    # -- introspection (the UI's "thresholds" view) ---------------------------

    def snapshot(self, limit: int = 50) -> list[dict[str, float | int | str | bool]]:
        rows: list[dict[str, float | int | str | bool]] = []
        for host, bucket in self._scores.items():
            if not bucket:
                continue
            arr = np.fromiter(bucket, dtype=np.float64, count=len(bucket))
            rows.append({
                "host": host,
                "samples": len(bucket),
                "median": float(np.median(arr)),
                "p99": float(np.quantile(arr, 0.99)),
                "threshold": self.threshold(host),
                "calibrated": self.is_host_calibrated(host),
                "raised": self.threshold(host) > settings.base_threshold + 1e-9,
            })
        rows.sort(key=lambda r: (-int(r["samples"]), str(r["host"])))
        return rows[:limit]
