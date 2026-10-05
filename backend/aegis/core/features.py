"""Feature engineering.

Two families of features are produced for every exported flow:

* **flow features** - intrinsic statistics of the conversation itself
  (volume, timing, packet-size distribution, TCP flag profile, payload entropy);
* **host features** - the behaviour of the *source host* inside two sliding
  windows (10 s / 60 s). These are what make fan-out attacks detectable: a single
  SYN to port 443 is unremarkable, 400 SYNs to 400 ports in 10 s is not.

`FEATURE_NAMES` is the single source of truth for ordering. Models are trained
and served through it, so a feature can never silently shift column.

Deliberate omission: the raw destination port is *not* a feature. A tree model
would happily memorise the lab's port numbers and report excellent scores that
collapse on real traffic. Only structural properties of the port are kept.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

from aegis.config import settings
from aegis.core.windows import FlowRecord, Window
from aegis.core.types import ACK, FIN, PSH, RST, SYN, URG, Flow, FlowKey, Packet

FLOW_FEATURES: tuple[str, ...] = (
    "duration",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "pkts_per_sec",
    "bytes_per_sec",
    "fwd_bwd_pkt_ratio",
    "down_up_byte_ratio",
    "mean_pkt_size",
    "std_pkt_size",
    "min_pkt_size",
    "max_pkt_size",
    "mean_iat",
    "std_iat",
    "min_iat",
    "max_iat",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "handshake_complete",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "mean_payload_len",
    "payload_entropy",
    "empty_payload_ratio",
    "dport_is_system",
)

HOST_FEATURES: tuple[str, ...] = (
    "host_flows_10s",
    "host_flows_60s",
    "host_distinct_dst_10s",
    "host_distinct_dst_60s",
    "host_distinct_dport_10s",
    "host_distinct_dport_60s",
    "host_syn_only_rate_10s",
    "host_failed_handshake_ratio_10s",
    "host_bytes_out_60s",
    "host_bytes_in_60s",
    "host_out_in_ratio_60s",
    "host_new_pair_ratio_60s",
    "host_mean_flow_duration_60s",
    "host_beacon_regularity",
    "host_dst_repeat_max_60s",
)

#: Destination-side window features. Source-side features alone cannot see a
#: flood whose source addresses are spoofed or botnet-wide: each individual
#: source looks quiet. Aggregating on the *victim* closes that hole.
DST_FEATURES: tuple[str, ...] = (
    "dst_flows_10s",
    "dst_distinct_src_10s",
    "dst_syn_only_rate_10s",
    "dst_failed_handshake_ratio_10s",
)

FEATURE_NAMES: tuple[str, ...] = FLOW_FEATURES + HOST_FEATURES + DST_FEATURES
FEATURE_INDEX: dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}

#: Human-readable labels used by the UI when explaining an alert.
FEATURE_LABELS: dict[str, str] = {
    "duration": "durée du flux (s)",
    "total_packets": "paquets échangés",
    "total_bytes": "octets échangés",
    "pkts_per_sec": "paquets/seconde",
    "bytes_per_sec": "octets/seconde",
    "fwd_bwd_pkt_ratio": "ratio paquets aller/retour",
    "down_up_byte_ratio": "ratio octets descendant/montant",
    "mean_pkt_size": "taille moyenne des paquets",
    "std_pkt_size": "variance de taille des paquets",
    "mean_iat": "intervalle moyen entre paquets",
    "std_iat": "régularité des intervalles",
    "syn_count": "nombre de SYN",
    "rst_count": "nombre de RST",
    "handshake_complete": "poignée de main TCP complétée",
    "payload_entropy": "entropie de la charge utile",
    "mean_payload_len": "taille moyenne de charge utile",
    "empty_payload_ratio": "part de paquets sans données",
    "host_flows_10s": "flux émis par l'hôte (10 s)",
    "host_flows_60s": "flux émis par l'hôte (60 s)",
    "host_distinct_dst_10s": "destinations distinctes (10 s)",
    "host_distinct_dport_10s": "ports distincts visés (10 s)",
    "host_distinct_dport_60s": "ports distincts visés (60 s)",
    "host_syn_only_rate_10s": "SYN sans réponse par seconde",
    "host_failed_handshake_ratio_10s": "part de connexions sans réponse",
    "host_bytes_out_60s": "octets sortants de l'hôte (60 s)",
    "host_out_in_ratio_60s": "ratio sortant/entrant de l'hôte",
    "host_new_pair_ratio_60s": "part de destinations jamais vues",
    "host_beacon_regularity": "régularité de type balise (beacon)",
    "host_dst_repeat_max_60s": "répétitions vers une même cible",
    "dst_flows_10s": "flux reçus par la cible (10 s)",
    "dst_distinct_src_10s": "sources distinctes vers la cible (10 s)",
    "dst_syn_only_rate_10s": "SYN/s reçus sans établissement",
    "dst_failed_handshake_ratio_10s": "part de connexions échouées sur la cible",
}


def label_for(feature: str) -> str:
    return FEATURE_LABELS.get(feature, feature.replace("_", " "))


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


@dataclass(slots=True)
class _Stat:
    """Streaming mean/std/min/max without storing the samples."""

    n: int = 0
    total: float = 0.0
    total_sq: float = 0.0
    lo: float = math.inf
    hi: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        self.total += x
        self.total_sq += x * x
        self.lo = min(self.lo, x)
        self.hi = max(self.hi, x)

    @property
    def mean(self) -> float:
        return _safe_div(self.total, self.n)

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        var = self.total_sq / self.n - self.mean**2
        return math.sqrt(max(var, 0.0))

    @property
    def min(self) -> float:
        return 0.0 if self.lo is math.inf else self.lo

    @property
    def max(self) -> float:
        return self.hi


class HostTracker:
    """Sliding-window behavioural profile of each *source* host.

    Two windows run in parallel (10 s and 60 s) on incremental aggregates, so
    cost per flow is independent of how busy the host is. The "pair already
    known" memory is global and capped; when full it drops its oldest quarter.
    """

    def __init__(self, max_pairs: int = 200_000) -> None:
        self._short: dict[str, Window] = {}
        self._long: dict[str, Window] = {}
        self._seen_pairs: dict[tuple[str, str, int], float] = {}
        self._max_pairs = max_pairs
        self.short_span = settings.host_window_short
        self.long_span = settings.host_window_long

    def _record(self, flow: Flow) -> FlowRecord:
        key = flow.key
        pair = (key.src, key.dst, key.dport)
        first_seen = self._seen_pairs.get(pair)
        if first_seen is None:
            if len(self._seen_pairs) >= self._max_pairs:
                for old in sorted(self._seen_pairs, key=self._seen_pairs.__getitem__)[: self._max_pairs // 4]:
                    del self._seen_pairs[old]
            self._seen_pairs[pair] = flow.end_ts
        return FlowRecord(
            ts=flow.end_ts,
            peer=key.dst,
            dport=key.dport,
            had_syn=bool(flow.features.get("syn_count", 0)),
            handshake_complete=bool(flow.features.get("handshake_complete", 0)),
            bytes_out=flow.fwd_bytes,
            bytes_in=flow.bwd_bytes,
            duration=flow.duration,
            new_pair=first_seen is None,
        )

    def observe(self, flow: Flow) -> None:
        rec = self._record(flow)
        src = flow.key.src
        short = self._short.get(src)
        if short is None:
            short = self._short[src] = Window(self.short_span)
            self._long[src] = Window(self.long_span, track_pair_times=True)
        long = self._long[src]
        short.push(rec)
        long.push(rec)
        short.trim(rec.ts)
        long.trim(rec.ts)

    def features(self, src: str, now: float) -> dict[str, float]:
        short, long = self._short.get(src), self._long.get(src)
        if short is None or long is None:
            return dict.fromkeys(HOST_FEATURES, 0.0)
        short.trim(now)
        long.trim(now)
        return {
            "host_flows_10s": float(short.n),
            "host_flows_60s": float(long.n),
            "host_distinct_dst_10s": float(short.distinct_peers),
            "host_distinct_dst_60s": float(long.distinct_peers),
            "host_distinct_dport_10s": float(short.distinct_dports),
            "host_distinct_dport_60s": float(long.distinct_dports),
            "host_syn_only_rate_10s": short.syn_only / self.short_span,
            "host_failed_handshake_ratio_10s": _safe_div(short.failed, short.with_syn),
            "host_bytes_out_60s": float(long.bytes_out),
            "host_bytes_in_60s": float(long.bytes_in),
            "host_out_in_ratio_60s": _safe_div(long.bytes_out, max(long.bytes_in, 1)),
            "host_new_pair_ratio_60s": _safe_div(long.new_pairs, long.n),
            "host_mean_flow_duration_60s": _safe_div(long.duration_sum, long.n),
            "host_beacon_regularity": long.beacon_regularity(),
            "host_dst_repeat_max_60s": float(long.max_pair_repeat),
        }

    def prune(self, now: float, idle: float = 600.0) -> None:
        """Forget hosts silent for `idle` seconds, so a long run stays bounded."""
        for src in [s for s, w in self._long.items() if w.is_empty]:
            self._long.pop(src, None)
            self._short.pop(src, None)


class PeerTracker:
    """Destination-side counterpart of `HostTracker`, short window only."""

    def __init__(self) -> None:
        self._windows: dict[str, Window] = {}
        self.span = settings.host_window_short

    def observe(self, flow: Flow) -> None:
        dst = flow.key.dst
        win = self._windows.get(dst)
        if win is None:
            win = self._windows[dst] = Window(self.span)
        win.push(
            FlowRecord(
                ts=flow.end_ts,
                peer=flow.key.src,
                dport=flow.key.dport,
                had_syn=bool(flow.features.get("syn_count", 0)),
                handshake_complete=bool(flow.features.get("handshake_complete", 0)),
                bytes_out=flow.bwd_bytes,
                bytes_in=flow.fwd_bytes,
                duration=flow.duration,
                new_pair=False,
            )
        )
        win.trim(flow.end_ts)

    def features(self, dst: str, now: float) -> dict[str, float]:
        win = self._windows.get(dst)
        if win is None:
            return dict.fromkeys(DST_FEATURES, 0.0)
        win.trim(now)
        return {
            "dst_flows_10s": float(win.n),
            "dst_distinct_src_10s": float(win.distinct_peers),
            "dst_syn_only_rate_10s": win.syn_only / self.span,
            "dst_failed_handshake_ratio_10s": _safe_div(win.failed, win.with_syn),
        }

    def prune(self, now: float) -> None:
        for dst in [d for d, w in self._windows.items() if w.is_empty]:
            self._windows.pop(dst, None)


@dataclass(slots=True)
class FlowAccumulator:
    """Per-flow mutable state, collapsed into a feature vector on export."""

    key: FlowKey
    start_ts: float
    last_ts: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    sizes: _Stat = field(default_factory=_Stat)
    iats: _Stat = field(default_factory=_Stat)
    payload_lens: _Stat = field(default_factory=_Stat)
    entropies: _Stat = field(default_factory=_Stat)
    empty_payloads: int = 0
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0
    saw_syn_fwd: bool = False
    saw_syn_ack_bwd: bool = False
    saw_ack_fwd_after: bool = False
    closed: bool = False
    label: str = "BENIGN"

    def add(self, pkt: Packet, forward: bool) -> None:
        if pkt.ts > self.last_ts:
            self.iats.add(pkt.ts - self.last_ts)
        self.last_ts = max(self.last_ts, pkt.ts)
        self.sizes.add(float(pkt.size))
        self.payload_lens.add(float(pkt.payload_len))
        if pkt.payload:
            from aegis.core.types import shannon_entropy

            self.entropies.add(shannon_entropy(pkt.payload))
        else:
            self.empty_payloads += 1

        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.size

        f = pkt.flags
        if f & SYN:
            self.syn += 1
            if forward and not (f & ACK):
                self.saw_syn_fwd = True
            if not forward and (f & ACK):
                self.saw_syn_ack_bwd = True
        if f & ACK:
            self.ack += 1
            if forward and self.saw_syn_ack_bwd:
                self.saw_ack_fwd_after = True
        if f & FIN:
            self.fin += 1
        if f & RST:
            self.rst += 1
            self.closed = True
        if f & PSH:
            self.psh += 1
        if f & URG:
            self.urg += 1
        if self.fin >= 2:
            self.closed = True
        if pkt.label != "BENIGN":
            self.label = pkt.label

    def flow_features(self) -> dict[str, float]:
        duration = max(self.last_ts - self.start_ts, 0.0)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        # A zero-duration flow (single packet) would make rates infinite; charge
        # it one millisecond so the rate stays large but finite and comparable.
        span = duration if duration > 0 else 1e-3
        handshake = 1.0 if (self.saw_syn_fwd and self.saw_syn_ack_bwd and self.saw_ack_fwd_after) else 0.0
        proto = self.key.proto
        return {
            "duration": duration,
            "fwd_packets": float(self.fwd_packets),
            "bwd_packets": float(self.bwd_packets),
            "total_packets": float(total_packets),
            "fwd_bytes": float(self.fwd_bytes),
            "bwd_bytes": float(self.bwd_bytes),
            "total_bytes": float(total_bytes),
            "pkts_per_sec": total_packets / span,
            "bytes_per_sec": total_bytes / span,
            "fwd_bwd_pkt_ratio": _safe_div(self.fwd_packets, max(self.bwd_packets, 1)),
            "down_up_byte_ratio": _safe_div(self.bwd_bytes, max(self.fwd_bytes, 1)),
            "mean_pkt_size": self.sizes.mean,
            "std_pkt_size": self.sizes.std,
            "min_pkt_size": self.sizes.min,
            "max_pkt_size": self.sizes.max,
            "mean_iat": self.iats.mean,
            "std_iat": self.iats.std,
            "min_iat": self.iats.min,
            "max_iat": self.iats.max,
            "syn_count": float(self.syn),
            "ack_count": float(self.ack),
            "fin_count": float(self.fin),
            "rst_count": float(self.rst),
            "psh_count": float(self.psh),
            "urg_count": float(self.urg),
            "handshake_complete": handshake,
            "is_tcp": 1.0 if proto == "tcp" else 0.0,
            "is_udp": 1.0 if proto == "udp" else 0.0,
            "is_icmp": 1.0 if proto == "icmp" else 0.0,
            "mean_payload_len": self.payload_lens.mean,
            "payload_entropy": self.entropies.mean,
            "empty_payload_ratio": _safe_div(self.empty_payloads, max(total_packets, 1)),
            "dport_is_system": 1.0 if self.key.dport < 1024 else 0.0,
        }
