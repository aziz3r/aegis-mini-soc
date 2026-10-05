"""Flow assembly: turns a packet stream into exported `Flow` records.

The table is driven by **packet timestamps**, never by wall-clock time. That is
what makes a PCAP replayed at x60 produce byte-identical flows to the same
traffic captured live - and it is what makes the golden tests deterministic.

Export triggers, in order of precedence:
  1. TCP teardown observed (RST, or FIN in both directions);
  2. idle timeout  - no packet for `flow_idle_timeout` seconds;
  3. active timeout - the flow has been open for `flow_active_timeout` seconds
     (a long download is exported in slices so the UI stays live).

Expiry uses two lazy min-heaps rather than scanning the active table. Scanning
was O(active flows) *per packet*, which degraded precisely under flood and
slowloris traffic - thousands of concurrent flows is their whole point. Each
packet now pushes one idle deadline; stale entries (the flow saw another packet,
or was already exported) are recognised by a per-flow generation counter and
discarded on pop, so the amortised cost is O(log n).
"""
from __future__ import annotations

import heapq
import itertools
from collections.abc import Iterable, Iterator

from aegis.config import settings
from aegis.core.features import FlowAccumulator, HostTracker, PeerTracker
from aegis.core.types import Flow, FlowKey, Packet

CanonicalKey = tuple[str, str, int, int, str]


def _effective_idle(acc: FlowAccumulator) -> float:
    """Idle timeout for this flow.

    An unanswered SYN is already a complete observation: nothing more will ever
    arrive. Holding it for the full 15 s idle timeout would add 15 s to the
    detection latency of every scan and flood - the two attacks made almost
    entirely of unanswered SYNs. Those are exported after `flow_syn_timeout`
    instead, which is what takes scan detection from ~16 s to ~3 s.
    """
    if acc.fwd_packets == 1 and acc.bwd_packets == 0 and acc.saw_syn_fwd:
        return settings.flow_syn_timeout
    return settings.flow_idle_timeout


class FlowTable:
    """Stateful packet -> flow assembler with bounded memory."""

    def __init__(self, max_active: int = 50_000, host_tracker: HostTracker | None = None) -> None:
        self._active: dict[CanonicalKey, tuple[FlowKey, FlowAccumulator]] = {}
        self._gen: dict[CanonicalKey, int] = {}
        self._counter = itertools.count(1)
        self._idle_heap: list[tuple[float, CanonicalKey, int]] = []
        self._active_heap: list[tuple[float, CanonicalKey, int]] = []
        self._max_active = max_active
        self.hosts = host_tracker or HostTracker()
        self.peers = PeerTracker()
        self.packets_seen = 0
        self.flows_exported = 0
        self._last_ts = 0.0

    # -- ingestion ------------------------------------------------------------

    def add(self, pkt: Packet) -> list[Flow]:
        """Absorb one packet; return the flows this packet caused to be exported."""
        self.packets_seen += 1
        self._last_ts = max(self._last_ts, pkt.ts)

        key = FlowKey(pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto)
        canon = key.canonical()
        entry = self._active.get(canon)
        if entry is None:
            acc = FlowAccumulator(key=key, start_ts=pkt.ts, last_ts=pkt.ts)
            self._active[canon] = (key, acc)
            gen = self._gen[canon] = next(self._counter)
            heapq.heappush(self._active_heap, (pkt.ts + settings.flow_active_timeout, canon, gen))
            acc.add(pkt, forward=True)
        else:
            init_key, acc = entry
            forward = (pkt.src, pkt.sport) == (init_key.src, init_key.sport)
            acc.add(pkt, forward=forward)
            gen = self._gen[canon]
        heapq.heappush(self._idle_heap, (acc.last_ts + _effective_idle(acc), canon, gen))

        exported: list[Flow] = []
        _, acc = self._active[canon]
        if acc.closed:
            exported.append(self._export(canon, pkt.ts))
        exported.extend(self.expire(pkt.ts))

        if len(self._active) > self._max_active:
            # Shed the oldest flows rather than growing without bound under flood.
            oldest = sorted(self._active, key=lambda k: self._active[k][1].last_ts)
            for canon_old in oldest[: len(self._active) - self._max_active]:
                exported.append(self._export(canon_old, pkt.ts))
        return exported

    def feed(self, packets: Iterable[Packet]) -> Iterator[Flow]:
        """Convenience generator for batch sources (pcap, dataset building)."""
        for pkt in packets:
            yield from self.add(pkt)
        yield from self.flush()

    # -- expiry ---------------------------------------------------------------

    def expire(self, now: float) -> list[Flow]:
        """Export flows whose idle or active timeout has elapsed at time `now`."""
        exported: list[Flow] = []
        heap = self._idle_heap
        while heap and heap[0][0] <= now:
            _, canon, gen = heapq.heappop(heap)
            entry = self._active.get(canon)
            if entry is None or self._gen.get(canon) != gen:
                continue                      # already exported, or key reused
            if (now - entry[1].last_ts) < _effective_idle(entry[1]):
                continue                      # refreshed by a later packet
            exported.append(self._export(canon, now))
        heap = self._active_heap
        while heap and heap[0][0] <= now:
            _, canon, gen = heapq.heappop(heap)
            if canon in self._active and self._gen.get(canon) == gen:
                exported.append(self._export(canon, now))
        return exported

    def flush(self) -> list[Flow]:
        """Export every remaining flow (end of capture)."""
        return [self._export(canon, self._last_ts) for canon in list(self._active)]

    # -- internals ------------------------------------------------------------

    def _export(self, canon: CanonicalKey, now: float) -> Flow:
        key, acc = self._active.pop(canon)
        self._gen.pop(canon, None)
        features = acc.flow_features()
        flow = Flow(
            key=key,
            start_ts=acc.start_ts,
            end_ts=acc.last_ts,
            features=features,
            label=acc.label,
            export_ts=max(now, acc.last_ts),
            fwd_packets=acc.fwd_packets,
            bwd_packets=acc.bwd_packets,
            fwd_bytes=acc.fwd_bytes,
            bwd_bytes=acc.bwd_bytes,
        )
        # The host profile must include this flow: a scan's 300th SYN should see
        # the 299 that preceded it. Only past and present data is ever used.
        self.hosts.observe(flow)
        self.peers.observe(flow)
        flow.features.update(self.hosts.features(key.src, acc.last_ts))
        flow.features.update(self.peers.features(key.dst, acc.last_ts))
        self.flows_exported += 1
        return flow

    @property
    def active_flows(self) -> int:
        return len(self._active)
