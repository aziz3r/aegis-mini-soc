"""Write lab traffic to a real .pcap file, without scapy.

Why not scapy: building and serialising a scapy object per packet made a 300 s
capture take over ten minutes and produce 70+ MB. The frames here are assembled
directly with `struct`, which is roughly two orders of magnitude faster.

Two details that matter for fidelity:

* **Snaplen.** Only the first `SNAPLEN` bytes of each frame are stored, but the
  record keeps the frame's *original* length. That is exactly what pcap's
  `incl_len` / `orig_len` pair is for, it is what `tcpdump -s` does, and it keeps
  byte counters exact while cutting the file size several-fold. The reader uses
  `wirelen`, so a replayed capture produces the same features as the live run.
* **Payload.** The snaplen is chosen to retain the whole 256-byte payload sample
  the generator produces, so payload entropy is identical on replay.

The result opens in Wireshark like any other capture.
"""
from __future__ import annotations

import struct
from pathlib import Path

from aegis.core.types import Packet

ETHERNET = 14
IP_HDR = 20
TCP_HDR = 20
UDP_HDR = 8
ICMP_HDR = 8
PAYLOAD_SAMPLE = 256
#: Ethernet + IP + TCP + the full payload sample, so nothing the feature
#: extractor looks at is ever truncated.
SNAPLEN = ETHERNET + IP_HDR + TCP_HDR + PAYLOAD_SAMPLE

_PCAP_MAGIC = 0xA1B2C3D4
_LINKTYPE_ETHERNET = 1
_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}

_GLOBAL_HEADER = struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, _LINKTYPE_ETHERNET)
_REC = struct.Struct("<IIII")
_ETH = struct.Struct("!6s6sH")
_IP = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBBHHH")
_UDP = struct.Struct("!HHHH")
_ICMP = struct.Struct("!BBHHH")


def _mac(ip: str) -> bytes:
    """A stable locally-administered MAC per address, so hosts look consistent."""
    octets = [int(part) & 0xFF for part in (ip.split(".") + ["0", "0", "0", "0"])[:4]]
    return bytes([0x02, 0x00, *octets])


def _ip_bytes(ip: str) -> bytes:
    try:
        return bytes(int(p) & 0xFF for p in ip.split(".")[:4])
    except ValueError:
        return b"\x00\x00\x00\x00"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(pkt: Packet) -> tuple[bytes, int]:
    """Build the captured bytes and report the frame's original length."""
    proto = _PROTO.get(pkt.proto, 253)
    payload = pkt.payload[:PAYLOAD_SAMPLE]

    if pkt.proto == "tcp":
        transport = _TCP.pack(pkt.sport, pkt.dport, 0, 0, 0x50, pkt.flags & 0xFF, 8192, 0, 0)
    elif pkt.proto == "udp":
        udp_len = UDP_HDR + max(pkt.size - ETHERNET - IP_HDR - UDP_HDR, 0)
        transport = _UDP.pack(pkt.sport, pkt.dport, udp_len, 0)
    elif pkt.proto == "icmp":
        transport = _ICMP.pack(pkt.dport & 0xFF, 0, 0, 1, 1)
    else:
        transport = b""

    orig_len = max(pkt.size, ETHERNET + IP_HDR + len(transport) + len(payload))
    ip_total = orig_len - ETHERNET

    header = _IP.pack(0x45, 0, ip_total & 0xFFFF, 0, 0x4000, 64, proto, 0,
                      _ip_bytes(pkt.src), _ip_bytes(pkt.dst))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]

    eth = _ETH.pack(_mac(pkt.dst), _mac(pkt.src), 0x0800)
    captured = (eth + header + transport + payload)[:SNAPLEN]
    return captured, orig_len


def _split_timestamp(ts: float) -> tuple[int, int]:
    """Seconds and microseconds, carrying correctly.

    Rounding the fractional part on its own can produce 1 000 000 microseconds,
    which wraps to 0 while the second stays put - the timestamp then jumps a full
    second into the past, and an out-of-order capture silently splits flows.
    """
    seconds = int(ts)
    micros = int(round((ts - seconds) * 1_000_000))
    if micros >= 1_000_000:
        seconds += 1
        micros -= 1_000_000
    elif micros < 0:
        seconds -= 1
        micros += 1_000_000
    return seconds, micros


def write_pcap(path: Path, packets, progress=None) -> tuple[int, Path]:
    """Write `packets` to `path`; returns (count, path)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("wb", buffering=1 << 20) as fh:
        fh.write(_GLOBAL_HEADER)
        for pkt in packets:
            captured, orig_len = _frame(pkt)
            seconds, micros = _split_timestamp(pkt.ts)
            fh.write(_REC.pack(seconds, micros, len(captured), orig_len))
            fh.write(captured)
            count += 1
            if progress and count % 100_000 == 0:
                progress(f"      {count:,} paquets écrits…")
    return count, path
