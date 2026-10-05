"""Incremental sliding-window aggregates.

The naive implementation recomputed every window statistic by walking the whole
window for each exported flow. That is O(n * w) and it collapses exactly when it
matters most: during a flood one host holds thousands of records in its 60 s
window, which is precisely when flows arrive fastest.

Everything here is therefore maintained incrementally - O(1) amortised per flow,
with multiset counters for the "distinct" statistics so cardinality is a `len()`
rather than a set rebuild.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field


@dataclass(slots=True)
class FlowRecord:
    """The minimum a window needs to remember about an exported flow."""

    ts: float
    peer: str            # destination host (source host, for a dst-side window)
    dport: int
    had_syn: bool
    handshake_complete: bool
    bytes_out: int
    bytes_in: int
    duration: float
    new_pair: bool       # this (src, dst, dport) had never been observed before


#: Inter-arrival samples kept per destination pair for the periodicity estimate.
#: Twelve gaps is plenty for a coefficient of variation and keeps a flood from
#: growing an unbounded timestamp list.
_PAIR_TS_CAP = 13


class Window:
    """Time-bounded multiset of flow records with O(1) aggregate access."""

    __slots__ = (
        "span", "_records", "_peers", "_dports", "_pairs", "_pair_ts",
        "n", "with_syn", "failed", "syn_only", "bytes_out", "bytes_in",
        "duration_sum", "new_pairs",
    )

    def __init__(self, span: float, track_pair_times: bool = False) -> None:
        self.span = span
        self._records: deque[FlowRecord] = deque()
        self._peers: dict[str, int] = {}
        self._dports: dict[int, int] = {}
        self._pairs: dict[tuple[str, int], int] = {}
        self._pair_ts: dict[tuple[str, int], deque[float]] | None = {} if track_pair_times else None
        self.n = 0
        self.with_syn = 0
        self.failed = 0
        self.syn_only = 0
        self.bytes_out = 0
        self.bytes_in = 0
        self.duration_sum = 0.0
        self.new_pairs = 0

    # -- mutation -------------------------------------------------------------

    def push(self, rec: FlowRecord) -> None:
        self._records.append(rec)
        self.n += 1
        self._peers[rec.peer] = self._peers.get(rec.peer, 0) + 1
        self._dports[rec.dport] = self._dports.get(rec.dport, 0) + 1
        pair = (rec.peer, rec.dport)
        self._pairs[pair] = self._pairs.get(pair, 0) + 1
        if self._pair_ts is not None:
            ts_list = self._pair_ts.setdefault(pair, deque(maxlen=_PAIR_TS_CAP))
            ts_list.append(rec.ts)
        if rec.had_syn:
            self.with_syn += 1
            if not rec.handshake_complete:
                self.failed += 1
                self.syn_only += 1
        self.bytes_out += rec.bytes_out
        self.bytes_in += rec.bytes_in
        self.duration_sum += rec.duration
        if rec.new_pair:
            self.new_pairs += 1

    def trim(self, now: float) -> None:
        cutoff = now - self.span
        recs = self._records
        while recs and recs[0].ts < cutoff:
            self._evict(recs.popleft())

    def _evict(self, rec: FlowRecord) -> None:
        self.n -= 1
        if (c := self._peers.get(rec.peer, 0)) <= 1:
            self._peers.pop(rec.peer, None)
        else:
            self._peers[rec.peer] = c - 1
        if (c := self._dports.get(rec.dport, 0)) <= 1:
            self._dports.pop(rec.dport, None)
        else:
            self._dports[rec.dport] = c - 1
        pair = (rec.peer, rec.dport)
        if (c := self._pairs.get(pair, 0)) <= 1:
            self._pairs.pop(pair, None)
            if self._pair_ts is not None:
                self._pair_ts.pop(pair, None)
        else:
            self._pairs[pair] = c - 1
        if rec.had_syn:
            self.with_syn -= 1
            if not rec.handshake_complete:
                self.failed -= 1
                self.syn_only -= 1
        self.bytes_out -= rec.bytes_out
        self.bytes_in -= rec.bytes_in
        self.duration_sum -= rec.duration
        if rec.new_pair:
            self.new_pairs -= 1

    # -- aggregates -----------------------------------------------------------

    @property
    def distinct_peers(self) -> int:
        return len(self._peers)

    @property
    def distinct_dports(self) -> int:
        return len(self._dports)

    @property
    def max_pair_repeat(self) -> int:
        return max(self._pairs.values(), default=0)

    @property
    def is_empty(self) -> bool:
        return self.n == 0

    def beacon_regularity(self) -> float:
        """1.0 = metronome-like contact with one peer, 0.0 = irregular.

        A C2 implant checks in on a timer. Computed as 1 - the coefficient of
        variation of inter-flow gaps towards the most-contacted peer, so jitter
        of a few percent (what real implants use) still scores high.
        """
        if not self._pair_ts:
            return 0.0
        best = max(self._pair_ts.values(), key=len)
        if len(best) < 4:
            return 0.0
        times = sorted(best)
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < 3:
            return 0.0
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            return 0.0
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        return max(0.0, min(1.0, 1.0 - math.sqrt(var) / mean))
