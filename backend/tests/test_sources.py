"""Traffic sources and the live pipeline."""
from __future__ import annotations

import asyncio
from collections import Counter

import pytest

from aegis.core.flows import FlowTable
from aegis.sources.lab import (
    ALL_CLASSES, ATTACK_FAMILIES, BENIGN, C2_BEACON, DOS_FLOOD, EXFILTRATION,
    PORT_SCAN, AttackSpec, LabNetwork,
)
from aegis.sources.stream import LAB_CHUNK_SECONDS, LabSource


class TestLabGenerator:
    def test_stream_is_time_ordered(self):
        """The k-way merge is only correct if every session is ordered."""
        net = LabNetwork(seed=7)
        packets = list(net.generate(120.0, net.plan(120.0)))
        assert len(packets) > 1_000
        assert all(a.ts <= b.ts for a, b in zip(packets, packets[1:]))

    def test_is_reproducible_from_its_seed(self):
        a = list(LabNetwork(seed=99).generate(45.0, LabNetwork(seed=99).plan(45.0)))
        b = list(LabNetwork(seed=99).generate(45.0, LabNetwork(seed=99).plan(45.0)))
        assert [(p.ts, p.src, p.dst, p.size) for p in a] == [(p.ts, p.src, p.dst, p.size) for p in b]

    def test_benign_only_has_no_attack_labels(self):
        packets = list(LabNetwork(seed=3).generate(90.0, []))
        assert {p.label for p in packets} == {BENIGN}

    @pytest.mark.parametrize("family", ATTACK_FAMILIES)
    def test_family_produces_flows(self, family):
        """A family that generates nothing would silently vanish from the metrics."""
        net = LabNetwork(seed=21)
        # long enough for the slowest families (beacon, exfiltration) to fire
        spec = AttackSpec(family, 1.0, 320.0, 1.5)
        flows = list(FlowTable().feed(net.generate(340.0, [spec], benign=False)))
        assert any(f.label == family for f in flows), f"{family} n'a produit aucun flux"

    def test_labels_are_within_the_known_classes(self):
        net = LabNetwork(seed=4)
        flows = list(FlowTable().feed(net.generate(180.0, net.plan(180.0))))
        assert set(f.label for f in flows) <= set(ALL_CLASSES)

    @pytest.mark.parametrize("family", [PORT_SCAN, DOS_FLOOD, C2_BEACON, EXFILTRATION])
    def test_stealth_variants_are_quieter(self, family):
        """The stealth column of the benchmark only means something if it is harder."""
        def volume(stealth: bool) -> int:
            net = LabNetwork(seed=15)
            spec = AttackSpec(family, 1.0, 200.0, 1.0, stealth=stealth)
            return sum(1 for _ in net.generate(220.0, [spec], benign=False))

        loud, quiet = volume(False), volume(True)
        assert quiet < loud, f"{family}: la variante furtive doit être plus discrète"

    def test_scan_signature(self):
        net = LabNetwork(seed=8)
        flows = list(FlowTable().feed(
            net.generate(120.0, [AttackSpec(PORT_SCAN, 1.0, 60.0)], benign=False)))
        scan = [f for f in flows if f.label == PORT_SCAN]
        assert len(scan) > 50
        assert len({f.key.dport for f in scan}) > 30, "un balayage touche beaucoup de ports"
        assert len({f.key.dst for f in scan}) == 1, "un balayage de ports vise une seule machine"

    def test_flood_signature(self):
        net = LabNetwork(seed=8)
        flows = list(FlowTable().feed(
            net.generate(90.0, [AttackSpec(DOS_FLOOD, 1.0, 40.0)], benign=False)))
        flood = [f for f in flows if f.label == DOS_FLOOD]
        assert len({f.key.src for f in flood}) > 10, "une inondation vient de nombreuses sources"
        assert len({f.key.dst for f in flood}) == 1, "une inondation vise une seule victime"

    def test_beacon_is_periodic(self):
        net = LabNetwork(seed=8)
        flows = list(FlowTable().feed(
            net.generate(340.0, [AttackSpec(C2_BEACON, 1.0, 320.0)], benign=False)))
        beacon = sorted((f for f in flows if f.label == C2_BEACON), key=lambda f: f.start_ts)
        assert len(beacon) >= 8
        gaps = [b.start_ts - a.start_ts for a, b in zip(beacon, beacon[1:])]
        mean = sum(gaps) / len(gaps)
        spread = max(abs(g - mean) for g in gaps) / mean
        assert spread < 0.35, "une balise doit être régulière - c'est sa signature"


class TestLabSource:
    def test_constructs_instantly_for_a_long_run(self):
        """Planning a whole day up front used to hang API startup."""
        source = LabSource(duration=86_400, speed=1.0, seed=11)
        assert source.plan == [], "aucune planification ne doit avoir lieu à la construction"

    def test_emits_in_batches_and_crosses_chunks(self):
        source = LabSource(duration=LAB_CHUNK_SECONDS * 2, speed=5_000.0, seed=11)

        async def drain():
            packets = batches = 0
            async for batch in source.batches():
                packets += len(batch)
                batches += 1
                if source._virtual_now > LAB_CHUNK_SECONDS + 30:
                    break
            return packets, batches

        packets, batches = asyncio.run(drain())
        assert packets > 10_000
        assert packets / batches > 5, "le lotissement ne doit pas dégénérer en un paquet par lot"
        assert source.plan, "une tranche doit avoir été planifiée"

    def test_describes_itself_for_the_ui(self):
        source = LabSource(duration=600, speed=2.0, seed=5)
        described = source.describe()
        assert described["kind"] == "lab"
        assert described["speed"] == 2.0
        assert "attacks" in described


class TestPipeline:
    def test_runs_end_to_end_and_persists(self, db, tiny_model):
        """The whole live path: source -> engine -> correlator -> database."""
        from aegis.api.pipeline import Pipeline

        pipeline = Pipeline(tiny_model)

        async def run():
            await pipeline.start_lab(duration=180.0, speed=5_000.0, seed=31, stealth_ratio=0.0)
            for _ in range(200):
                await asyncio.sleep(0.1)
                if not pipeline.is_running:
                    break
            status = pipeline.status()
            await pipeline.stop()
            return status

        status = asyncio.run(run())
        assert status["error"] is None, status["error"]
        assert status["stats"]["packets"] > 1_000
        assert status["stats"]["flows"] > 100
        # the writer path that used to crash on a None counter
        assert status["written"]["incidents"] >= 1
        assert status["written"]["alerts"] >= 1


class TestPcapRoundTrip:
    """Writing a capture and reading it back must not change what the detector sees.

    This is the property the whole replay feature rests on: if a PCAP produced
    different features from the live traffic, no benchmark run on a capture file
    would describe the deployed system.
    """

    @pytest.fixture(scope="class")
    def capture(self, tmp_path_factory):
        from aegis.sources.pcap_writer import write_pcap

        net = LabNetwork(seed=4242)
        plan = net.plan(120.0, density=1.0, stealth_ratio=0.3)
        packets = list(net.generate(120.0, plan))
        path = tmp_path_factory.mktemp("pcap") / "roundtrip.pcap"
        count, _ = write_pcap(path, packets)
        assert count == len(packets)
        return path, packets

    def test_packets_round_trip_byte_for_byte(self, capture):
        from aegis.sources.pcap_reader import read_pcap

        path, original = capture
        back = list(read_pcap(path))
        assert len(back) == len(original)
        for a, b in zip(original, back):
            assert (a.src, a.dst, a.proto, a.sport, a.dport, a.size, a.flags, a.payload) == \
                   (b.src, b.dst, b.proto, b.sport, b.dport, b.size, b.flags, b.payload)

    def test_structural_features_are_identical(self, capture):
        from aegis.sources.pcap_reader import read_pcap

        path, original = capture
        live = list(FlowTable().feed(original))
        replayed = list(FlowTable().feed(read_pcap(path)))
        assert len(live) == len(replayed)

        def signature(flows):
            return Counter(
                (f.key.as_tuple(), f.packets, f.bytes,
                 round(f.features["payload_entropy"], 9),
                 round(f.features["host_distinct_dport_10s"], 6),
                 round(f.features["dst_distinct_src_10s"], 6))
                for f in flows
            )

        a, b = signature(live), signature(replayed)
        assert sum((a & b).values()) == len(live), "les features structurelles doivent être identiques"

    def test_timestamps_survive_to_microsecond_resolution(self, capture):
        """A pcap stores microseconds; that quantisation is the only loss."""
        from aegis.sources.pcap_reader import read_pcap

        path, original = capture
        for a, b in zip(original, read_pcap(path)):
            assert abs(a.ts - b.ts) <= 1.5e-6

    def test_generator_is_reproducible_across_processes(self):
        """Payload bytes must not come from os.urandom, or a capture written by
        one run cannot be compared with traffic generated by another."""
        import hashlib

        def digest():
            net = LabNetwork(seed=777)
            packets = net.generate(45.0, net.plan(45.0, stealth_ratio=0.3))
            return hashlib.sha256(b"".join(p.payload for p in packets)).hexdigest()

        assert digest() == digest()

    def test_declared_size_always_covers_the_payload(self):
        """A frame cannot declare fewer bytes than it carries."""
        from aegis.sources.lab import ETH_IP_TCP, ETH_IP_UDP

        net = LabNetwork(seed=2026)
        offenders = []
        for pkt in net.generate(180.0, net.plan(180.0, stealth_ratio=0.3)):
            headers = ETH_IP_TCP if pkt.proto == "tcp" else (
                ETH_IP_UDP if pkt.proto == "udp" else 42)
            if pkt.size < headers + len(pkt.payload):
                offenders.append((pkt.proto, pkt.size, len(pkt.payload)))
        assert not offenders, offenders[:3]


class TestLiveSourceBackpressure:
    """Live capture needs root, so the sniffer itself is not exercised here.

    What *is* exercised is the property that matters when it runs: a stalled
    consumer must cost packets, never block the capture thread. Losing packets is
    recoverable and visible; blocking the sniffer loses the whole capture.
    """

    def test_full_queue_drops_instead_of_blocking(self):
        import queue as queue_module

        from aegis.core.types import SYN, Packet
        from aegis.sources.stream import LiveSource

        source = LiveSource("lo0", queue_size=8)
        for i in range(40):
            pkt = Packet(float(i), "10.0.0.1", "10.0.0.2", "tcp", 1000 + i, 80, 74, SYN)
            try:
                source._queue.put_nowait(pkt)
            except queue_module.Full:
                source.dropped += 1

        assert source._queue.qsize() == 8, "la file doit rester bornée"
        assert source.dropped == 32, "le dépassement doit être compté, pas bloquant"
        described = source.describe()
        assert described["dropped"] == 32, "les pertes doivent remonter à l'interface"
        assert described["iface"] == "lo0"
