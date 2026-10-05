"""Packet sources for the live pipeline.

Three implementations behind one interface, so the engine cannot tell them apart:

  `LabSource`   the synthetic network, paced in real time (the demo)
  `PcapSource`  a capture file, replayed at a chosen speed (the honest test)
  `LiveSource`  a real interface via scapy (requires root)

All of them yield *batches* of packets. Batching is what keeps throughput up:
scoring 512 flows in one vectorised call costs barely more than scoring one.

A note on time. `Packet.ts` always carries the **capture** timeline, never wall
clock, because flow timeouts are expressed in capture time - replaying a PCAP at
x60 must produce the same flows as the original capture. Wall-clock arrival time
is recorded separately by the pipeline for display.
"""
from __future__ import annotations

import asyncio
import queue
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

from aegis.core.types import ACK, FIN, PSH, RST, SYN, URG, Packet
from aegis.sources.lab import ATTACK_FAMILIES, AttackSpec, LabNetwork

PAYLOAD_SAMPLE = 256
BATCH_MAX = 512
#: Simulated/captured seconds released per pacing step. Small enough that a
#: real-time demo updates several times a second, large enough that batches
#: stay worth vectorising.
SLICE_SECONDS = 0.25


class Source(ABC):
    """A finite or infinite stream of packet batches."""

    name: str = "source"
    kind: str = "generic"

    def __init__(self) -> None:
        self.packets_emitted = 0
        self.started_at = 0.0
        self.finished = False

    @abstractmethod
    def batches(self) -> AsyncIterator[list[Packet]]:
        ...

    @property
    def progress(self) -> float | None:
        """0..1 when the total is known, else None."""
        return None

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "kind": self.kind,
            "packets": self.packets_emitted,
            "progress": self.progress,
            "finished": self.finished,
        }

    async def close(self) -> None:
        return None


# --------------------------------------------------------------------- lab

#: Simulated seconds built at a time by `LabSource`.
#:
#: The generator plans every session of a period up front, so asking it for a
#: 24-hour period meant building roughly half a million session generators before
#: emitting a single packet - API startup simply hung. Traffic is therefore built
#: one chunk at a time: memory stays bounded, the first packet arrives instantly,
#: and a source can run indefinitely. The cost is that a session still open at a
#: chunk boundary is cut there, which is why the chunk is much longer than any
#: ordinary session.
LAB_CHUNK_SECONDS = 600.0


class LabSource(Source):
    """The synthetic network, paced so one simulated second takes 1/speed real seconds."""

    kind = "lab"

    def __init__(self, duration: float = 3600.0, speed: float = 1.0, seed: int | None = None,
                 density: float = 1.0, stealth_ratio: float = 0.25,
                 families: tuple[str, ...] = ATTACK_FAMILIES) -> None:
        super().__init__()
        self.duration = duration
        self.speed = max(speed, 0.0)
        self.seed = seed if seed is not None else int(time.time()) % 100_000
        self.density = density
        self.stealth_ratio = stealth_ratio
        self.families = families
        self.network = LabNetwork(seed=self.seed)
        self.name = f"lab#{self.seed}"
        self._virtual_now = 0.0
        self._chunk_offset = 0.0
        #: the plan of the chunk currently being emitted, for the UI
        self.plan: list[AttackSpec] = []

    def batches(self) -> AsyncIterator[list[Packet]]:
        return self._run()

    def _chunks(self) -> Iterator[tuple[float, Iterator[Packet]]]:
        """Yield (time offset, packet stream) one simulated period at a time."""
        remaining = self.duration
        offset = 0.0
        while remaining > 0:
            span = min(LAB_CHUNK_SECONDS, remaining)
            self.plan = self.network.plan(
                span, families=self.families, density=self.density,
                stealth_ratio=self.stealth_ratio,
            )
            yield offset, self.network.generate(span, self.plan)
            offset += span
            remaining -= span

    async def _run(self) -> AsyncIterator[list[Packet]]:
        self.started_at = time.time()
        batch: list[Packet] = []
        # Traffic is released in quantised slices of simulated time. Pacing on
        # every packet timestamp instead would flush a batch per packet and throw
        # away the whole point of batching.
        next_boundary = SLICE_SECONDS
        for offset, stream in self._chunks():
            self._chunk_offset = offset
            for pkt in stream:
                pkt.ts += offset           # chunk-local time -> run time
                self._virtual_now = pkt.ts
                batch.append(pkt)
                # with speed=0 (as fast as possible) only the batch size bounds a flush
                crossed = self.speed > 0 and pkt.ts >= next_boundary
                if crossed or len(batch) >= BATCH_MAX:
                    self.packets_emitted += len(batch)
                    yield batch
                    batch = []
                if crossed:
                    next_boundary = pkt.ts + SLICE_SECONDS
                    delay = self.started_at + pkt.ts / self.speed - time.time()
                    if delay > 0:
                        await asyncio.sleep(min(delay, 1.0))
        if batch:
            self.packets_emitted += len(batch)
            yield batch
        self.finished = True

    @property
    def progress(self) -> float | None:
        return min(self._virtual_now / self.duration, 1.0) if self.duration else None

    def describe(self) -> dict[str, object]:
        d = super().describe()
        d["attacks"] = [a.as_dict() for a in self.plan]
        d["seed"] = self.seed
        d["speed"] = self.speed
        d["simulated_seconds"] = round(self._virtual_now, 1)
        return d


# -------------------------------------------------------------------- pcap

def _scapy_to_packet(scapy_pkt) -> Packet | None:
    """Normalise a scapy packet into our `Packet`, or None if not IP."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in scapy_pkt:
        return None
    ip = scapy_pkt[IP]
    ts = float(getattr(scapy_pkt, "time", 0.0))
    # `wirelen` is the frame's length on the wire; `len()` is only what the
    # capture stored. They differ whenever a snaplen was used, and using the
    # latter would silently understate every byte counter in the features.
    size = int(getattr(scapy_pkt, "wirelen", None) or len(scapy_pkt))

    if TCP in scapy_pkt:
        tcp = scapy_pkt[TCP]
        flags = int(tcp.flags)
        bits = 0
        for mask, bit in ((0x01, FIN), (0x02, SYN), (0x04, RST), (0x08, PSH), (0x10, ACK), (0x20, URG)):
            if flags & mask:
                bits |= bit
        payload = bytes(tcp.payload)[:PAYLOAD_SAMPLE]
        return Packet(ts, ip.src, ip.dst, "tcp", int(tcp.sport), int(tcp.dport), size, bits, payload)
    if UDP in scapy_pkt:
        udp = scapy_pkt[UDP]
        return Packet(ts, ip.src, ip.dst, "udp", int(udp.sport), int(udp.dport), size, 0,
                      bytes(udp.payload)[:PAYLOAD_SAMPLE])
    if ICMP in scapy_pkt:
        icmp = scapy_pkt[ICMP]
        return Packet(ts, ip.src, ip.dst, "icmp", 0, int(icmp.type), size, 0,
                      bytes(icmp.payload)[:PAYLOAD_SAMPLE])
    return Packet(ts, ip.src, ip.dst, "other", 0, int(ip.proto), size, 0, b"")


class PcapSource(Source):
    """Replay a capture file. `speed=0` means as fast as the CPU allows."""

    kind = "pcap"

    def __init__(self, path: Path, speed: float = 10.0) -> None:
        super().__init__()
        self.path = Path(path)
        self.speed = max(speed, 0.0)
        self.name = self.path.name
        self.decoder = "natif"
        self.total_bytes = self.path.stat().st_size if self.path.exists() else 0
        self._first_ts: float | None = None
        self._last_ts = 0.0

    def batches(self) -> AsyncIterator[list[Packet]]:
        return self._run()

    async def _run(self) -> AsyncIterator[list[Packet]]:
        self.started_at = time.time()
        batch: list[Packet] = []
        loop = asyncio.get_running_loop()
        reader = self._open()
        try:
            while True:
                # Reading is blocking work; keep the event loop responsive.
                chunk = await loop.run_in_executor(None, self._read_chunk, reader)
                if not chunk:
                    break
                for pkt in chunk:
                    if self._first_ts is None:
                        self._first_ts = pkt.ts
                    self._last_ts = pkt.ts
                    batch.append(pkt)
                    if len(batch) >= BATCH_MAX:
                        self.packets_emitted += len(batch)
                        yield batch
                        batch = []
                if self.speed > 0 and self._first_ts is not None:
                    target = self.started_at + (self._last_ts - self._first_ts) / self.speed
                    delay = target - time.time()
                    if delay > 0:
                        await asyncio.sleep(min(delay, 1.0))
                else:
                    await asyncio.sleep(0)  # yield to the loop
        finally:
            close = getattr(reader, "close", None)
            if close is not None:
                close()
        if batch:
            self.packets_emitted += len(batch)
            yield batch
        self.finished = True

    def _open(self):
        """Prefer the fast native reader; fall back to scapy when it cannot help."""
        from aegis.sources.pcap_reader import UnsupportedCapture, read_pcap

        try:
            iterator = read_pcap(self.path)
            first = next(iterator, None)
            self.decoder = "natif"
            return _Prepended(first, iterator)
        except UnsupportedCapture as exc:
            self.decoder = f"scapy ({exc})"
            # scapy resolves the link type through its registry at construction,
            # so the layer classes must be imported before the reader is opened
            import scapy.layers.inet  # noqa: F401
            import scapy.layers.l2  # noqa: F401
            from scapy.utils import PcapReader

            return PcapReader(str(self.path))

    def _read_chunk(self, reader, n: int = BATCH_MAX) -> list[Packet]:
        out: list[Packet] = []
        if isinstance(reader, _Prepended):
            for pkt in reader:
                out.append(pkt)
                if len(out) >= n:
                    break
            return out
        for _ in range(n):
            try:
                raw = reader.read_packet()
            except (EOFError, StopIteration):
                break
            if raw is None:
                break
            pkt = _scapy_to_packet(raw)
            if pkt is not None:
                out.append(pkt)
        return out

    @property
    def progress(self) -> float | None:
        return None  # packet count is unknown until the file has been read

    def describe(self) -> dict[str, object]:
        d = super().describe()
        d["file"] = str(self.path)
        d["speed"] = self.speed
        d["capture_seconds"] = round(self._last_ts - (self._first_ts or self._last_ts), 1)
        d["decoder"] = self.decoder
        return d


# -------------------------------------------------------------------- live

class _Prepended:
    """An iterator with its first item put back, so a probe read is not lost.

    `close()` matters: the underlying generator holds the capture's file handle,
    and without it a replay leaks one descriptor per run.
    """

    __slots__ = ("_first", "_rest")

    def __init__(self, first, rest) -> None:
        self._first, self._rest = first, rest

    def __iter__(self):
        if self._first is not None:
            yield self._first
            self._first = None
        yield from self._rest

    def close(self) -> None:
        closer = getattr(self._rest, "close", None)
        if closer is not None:
            closer()


class LiveSource(Source):
    """Capture from a real interface. Requires root; scapy sniffs on a thread."""

    kind = "live"

    def __init__(self, iface: str, bpf: str = "ip", queue_size: int = 20_000) -> None:
        super().__init__()
        self.iface = iface
        self.bpf = bpf
        self.name = f"{iface} ({bpf})"
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._sniffer = None
        self.dropped = 0

    def batches(self) -> AsyncIterator[list[Packet]]:
        return self._run()

    async def _run(self) -> AsyncIterator[list[Packet]]:
        from scapy.sendrecv import AsyncSniffer

        self.started_at = time.time()

        def on_packet(raw) -> None:
            pkt = _scapy_to_packet(raw)
            if pkt is None:
                return
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                # Never block the sniffer thread: a stalled consumer must cost
                # packets, not the whole capture.
                self.dropped += 1

        self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=on_packet, store=False)
        self._sniffer.start()
        try:
            while True:
                batch: list[Packet] = []
                try:
                    batch.append(self._queue.get(timeout=0.5))
                except queue.Empty:
                    yield []            # keep the pipeline's housekeeping ticking
                    continue
                while len(batch) < BATCH_MAX:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
                self.packets_emitted += len(batch)
                yield batch
        finally:
            await self.close()

    async def close(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self.finished = True

    def describe(self) -> dict[str, object]:
        d = super().describe()
        d["iface"] = self.iface
        d["bpf"] = self.bpf
        d["dropped"] = self.dropped
        d["queued"] = self._queue.qsize()
        return d
