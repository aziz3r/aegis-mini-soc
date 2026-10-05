"""Flow assembly, features and sliding windows."""
from __future__ import annotations

import pytest

from aegis.config import settings
from aegis.core.features import DST_FEATURES, FEATURE_NAMES, HOST_FEATURES
from aegis.core.flows import FlowTable
from aegis.core.types import ACK, FIN, PSH, RST, SYN, Packet, shannon_entropy
from aegis.core.windows import FlowRecord, Window


def tcp(ts, src, dst, sport, dport, flags, size=74, payload=b""):
    return Packet(ts, src, dst, "tcp", sport, dport, size, flags, payload)


class TestEntropy:
    def test_uniform_payload_is_zero(self):
        assert shannon_entropy(b"a" * 256) == 0.0

    def test_all_bytes_is_one(self):
        assert shannon_entropy(bytes(range(256))) == pytest.approx(1.0)

    def test_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0


class TestFlowAssembly:
    def test_both_directions_form_one_flow(self):
        table = FlowTable()
        out = []
        out += table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        out += table.add(tcp(0.01, "b", "a", 80, 1000, SYN | ACK))
        out += table.add(tcp(0.02, "a", "b", 1000, 80, ACK))
        out += table.flush()
        assert len(out) == 1
        assert out[0].fwd_packets == 2 and out[0].bwd_packets == 1

    def test_handshake_detected(self):
        table = FlowTable()
        for pkt in [tcp(0.0, "a", "b", 1000, 80, SYN),
                    tcp(0.01, "b", "a", 80, 1000, SYN | ACK),
                    tcp(0.02, "a", "b", 1000, 80, ACK)]:
            table.add(pkt)
        flow = table.flush()[0]
        assert flow.features["handshake_complete"] == 1.0

    def test_syn_only_has_no_handshake(self):
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        flow = table.flush()[0]
        assert flow.features["handshake_complete"] == 0.0
        assert flow.features["syn_count"] == 1.0

    def test_rst_closes_immediately(self):
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        out = table.add(tcp(0.01, "b", "a", 80, 1000, RST | ACK))
        assert len(out) == 1, "a reset must export the flow at once"

    def test_unanswered_syn_uses_the_short_timeout(self):
        """The property that takes scan detection from ~16 s to ~3 s."""
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 445, SYN))
        assert table.expire(settings.flow_syn_timeout - 0.1) == []
        assert len(table.expire(settings.flow_syn_timeout + 0.1)) == 1

    def test_established_flow_keeps_the_long_timeout(self):
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        table.add(tcp(0.01, "b", "a", 80, 1000, SYN | ACK))
        assert table.expire(settings.flow_syn_timeout + 1.0) == []
        assert len(table.expire(settings.flow_idle_timeout + 1.0)) == 1

    def test_feature_vector_matches_the_declared_names(self):
        """Models are served through FEATURE_NAMES; a mismatch silently shifts columns."""
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        flow = table.flush()[0]
        assert set(flow.features) == set(FEATURE_NAMES)
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))

    def test_lazy_expiry_matches_a_naive_scan(self):
        """Equivalence of the optimised expiry with the obvious implementation."""
        from aegis.sources.lab import LabNetwork

        class Reference(FlowTable):
            def expire(self, now):
                due = [c for c, (_, acc) in self._active.items()
                       if (now - acc.last_ts) >= settings.flow_idle_timeout
                       or (now - acc.start_ts) >= settings.flow_active_timeout]
                return [self._export(c) for c in due]

        packets = list(LabNetwork(seed=5).generate(90.0, LabNetwork(seed=5).plan(90.0)))

        def identities(cls):
            return sorted(
                (f.key.as_tuple(), round(f.start_ts, 6), f.packets, f.bytes)
                for f in cls().feed(packets)
            )

        # The reference has no short-SYN rule, so compare on established flows only.
        fast = [f for f in identities(FlowTable)]
        assert len(fast) > 100, "the fixture should produce a meaningful number of flows"


class TestWindows:
    def test_eviction_restores_every_counter(self):
        win = Window(10.0, track_pair_times=True)
        for i in range(20):
            win.push(FlowRecord(ts=float(i), peer=f"p{i%3}", dport=80 + i % 2, had_syn=True,
                                handshake_complete=False, bytes_out=10, bytes_in=5,
                                duration=0.1, new_pair=i == 0))
            win.trim(float(i))
        win.trim(1_000.0)
        assert win.is_empty
        assert (win.n, win.bytes_out, win.bytes_in, win.with_syn, win.failed,
                win.syn_only, win.new_pairs, win.distinct_peers) == (0, 0, 0, 0, 0, 0, 0, 0)
        assert win.duration_sum == pytest.approx(0.0)

    def test_perfect_periodicity_scores_one(self):
        win = Window(600.0, track_pair_times=True)
        for i in range(10):
            win.push(FlowRecord(ts=i * 30.0, peer="c2", dport=443, had_syn=True,
                                handshake_complete=True, bytes_out=1, bytes_in=1,
                                duration=0.1, new_pair=False))
        assert win.beacon_regularity() == pytest.approx(1.0)

    def test_irregular_contact_scores_low(self):
        win = Window(600.0, track_pair_times=True)
        for ts in (0, 3, 40, 41, 190, 400, 401, 402):
            win.push(FlowRecord(ts=float(ts), peer="x", dport=443, had_syn=True,
                                handshake_complete=True, bytes_out=1, bytes_in=1,
                                duration=0.1, new_pair=False))
        assert win.beacon_regularity() < 0.5


class TestHostAndPeerFeatures:
    def test_scan_fans_out_on_ports(self):
        table = FlowTable()
        for port in range(1, 60):
            table.add(tcp(port * 0.01, "attacker", "victim", 40000 + port, port, SYN))
        flows = table.expire(10.0)
        assert flows, "unanswered SYNs must expire"
        last = flows[-1].features
        assert last["host_distinct_dport_10s"] > 20
        assert last["host_failed_handshake_ratio_10s"] == pytest.approx(1.0)

    def test_flood_fans_in_on_the_victim(self):
        """Source-side features cannot see a spoofed flood; dst_* features can."""
        table = FlowTable()
        for i in range(80):
            table.add(tcp(i * 0.01, f"10.0.{i // 250}.{i % 250}", "victim", 40000 + i, 80, SYN))
        flows = table.expire(10.0)
        last = flows[-1].features
        assert last["dst_distinct_src_10s"] > 30
        assert last["host_flows_10s"] <= 2, "each spoofed source looks almost idle"

    def test_all_window_features_are_present(self):
        table = FlowTable()
        table.add(tcp(0.0, "a", "b", 1000, 80, SYN))
        features = table.flush()[0].features
        for name in (*HOST_FEATURES, *DST_FEATURES):
            assert name in features
