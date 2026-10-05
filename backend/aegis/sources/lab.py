"""Synthetic lab network with ground-truth labels.

Why this exists. A detector is worthless without an honest measurement, and an
honest measurement needs labels. Capturing a real network gives you traffic but
no labels; the public IDS datasets (CIC-IDS2017, UNSW-NB15) give you labels but
are a multi-gigabyte download and are flow-level only, so they cannot exercise a
packet-level pipeline end to end.

So this module *generates packets*. Every packet carries the family it belongs
to, and it is fed through exactly the same `FlowTable` and feature extractor as
a real capture - nothing about the detection path is simulated. The traffic is
synthetic; the detection, the features, the model and the metrics are real.

Honest limits, stated up front:
  * packet contents are plausible, not protocol-perfect (no real TLS handshake);
  * benign behaviour is drawn from parametric distributions, so it is tidier
    than a real office LAN - expect real-world false positives to be higher
    than the benchmark suggests;
  * `aegis replay` on a real PCAP is the answer to both, and is supported.
"""
from __future__ import annotations

import heapq
import random
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Callable

from aegis.core.types import ACK, FIN, PSH, RST, SYN, Packet

MSS = 1460
ETH_IP_TCP = 54
ETH_IP_UDP = 42
SAMPLE = 256  # payload bytes retained per packet (bounds memory, enough for entropy)

BENIGN = "BENIGN"
PORT_SCAN = "PORT_SCAN"
NET_SCAN = "NET_SCAN"
DOS_FLOOD = "DOS_FLOOD"
SSH_BRUTEFORCE = "SSH_BRUTEFORCE"
WEB_BRUTEFORCE = "WEB_BRUTEFORCE"
SLOWLORIS = "SLOWLORIS"
DNS_TUNNEL = "DNS_TUNNEL"
EXFILTRATION = "EXFILTRATION"
C2_BEACON = "C2_BEACON"

ATTACK_FAMILIES: tuple[str, ...] = (
    PORT_SCAN,
    NET_SCAN,
    DOS_FLOOD,
    SSH_BRUTEFORCE,
    WEB_BRUTEFORCE,
    SLOWLORIS,
    DNS_TUNNEL,
    EXFILTRATION,
    C2_BEACON,
)
ALL_CLASSES: tuple[str, ...] = (BENIGN, *ATTACK_FAMILIES)


@dataclass(slots=True)
class AttackSpec:
    family: str
    start: float
    duration: float
    intensity: float = 1.0  # multiplies the attack's natural rate
    stealth: bool = False   # low-and-slow variant, deliberately hard to detect

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "start": round(self.start, 2),
            "duration": round(self.duration, 2),
            "intensity": self.intensity,
            "stealth": self.stealth,
        }


#: Rate multiplier applied when `AttackSpec.stealth` is set (1.0 = loud rate).
#: A loud attack is a straight line on a chart; a patient one hides inside the
#: variance of normal traffic. Reporting both is the only way a recall figure
#: means anything: the loud numbers say the pipeline works, the stealth numbers
#: say where it stops working.
STEALTH_RATE: dict[str, float] = {
    PORT_SCAN: 0.015,
    NET_SCAN: 0.025,
    DOS_FLOOD: 0.06,
    SSH_BRUTEFORCE: 0.035,
    WEB_BRUTEFORCE: 0.03,
    DNS_TUNNEL: 0.07,
}


#: (min duration, max duration, windows per 10 min) per family. A port scan is
#: over in a minute; a beacon or a staged exfiltration only becomes visible over
#: several minutes, and needs a long window to contribute enough samples.
WINDOW_PROFILE: dict[str, tuple[float, float, float]] = {
    PORT_SCAN: (25.0, 60.0, 1.0),
    NET_SCAN: (25.0, 60.0, 1.0),
    DOS_FLOOD: (20.0, 45.0, 1.0),
    SSH_BRUTEFORCE: (40.0, 90.0, 1.0),
    WEB_BRUTEFORCE: (40.0, 90.0, 1.0),
    SLOWLORIS: (90.0, 200.0, 1.0),
    DNS_TUNNEL: (60.0, 140.0, 1.0),
    EXFILTRATION: (90.0, 240.0, 1.5),
    C2_BEACON: (150.0, 320.0, 1.5),
}
_DEFAULT_WINDOW = (25.0, 70.0, 1.0)


@dataclass(slots=True)
class Topology:
    """Who exists on the virtual network."""

    clients: list[str] = field(default_factory=lambda: [f"192.168.1.{i}" for i in range(20, 81)])
    web: str = "192.168.1.10"
    db: str = "192.168.1.11"
    dns: str = "192.168.1.12"
    files: str = "192.168.1.13"
    gateway: str = "192.168.1.1"
    external: list[str] = field(
        default_factory=lambda: [
            "140.82.121.4", "151.101.1.69", "104.18.32.47", "13.107.42.14",
            "142.250.75.238", "17.253.144.10", "52.97.146.162", "99.84.108.33",
        ]
    )
    attackers: list[str] = field(default_factory=lambda: ["185.220.101.47", "45.133.1.88", "193.27.14.202"])
    #: an internal machine the attacker already owns - origin of exfil / beacon
    compromised: str = "192.168.1.57"
    c2: str = "91.219.236.14"

    @property
    def servers(self) -> list[str]:
        return [self.web, self.db, self.dns, self.files]


_POOL_SIZE = 1 << 16
_POOLS: dict[str, bytes] | None = None

#: The pools are built from a *fixed* seed, independent of the network's own RNG.
#: `os.urandom` was used for the encrypted pool and had to go: it made the same
#: scenario seed produce the same flows with different payload bytes in every
#: process, so a capture written by one run could not be compared against traffic
#: generated by another. Entropy is identical either way.
_POOL_SEED = 20_260_101


def _build_pools() -> dict[str, bytes]:
    rng = random.Random(_POOL_SEED)
    text = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/.-_=&?"
    base32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return {
        "text": bytes(rng.choice(text) for _ in range(_POOL_SIZE)),
        "base32": bytes(rng.choice(base32) for _ in range(_POOL_SIZE)),
        "encrypted": rng.randbytes(_POOL_SIZE),
        "zeros": bytes(_POOL_SIZE),
    }


def _payload(n: int, kind: str, rng: random.Random) -> bytes:
    """A payload *sample* whose entropy matches the traffic kind.

    Drawing bytes one RNG call at a time dominated generation. Samples are slices
    of pre-built pools instead: same entropy profile per kind, none of the cost.
    """
    global _POOLS
    n = min(n, SAMPLE)
    if n <= 0:
        return b""
    if _POOLS is None:
        _POOLS = _build_pools()
    pool = _POOLS.get(kind) or _POOLS["text"]
    offset = rng.randrange(0, _POOL_SIZE - SAMPLE)
    return pool[offset:offset + n]


class LabNetwork:
    """Generates a time-ordered, labelled packet stream."""

    def __init__(self, seed: int = 1337, topology: Topology | None = None) -> None:
        self.rng = random.Random(seed)
        self.net = topology or Topology()

    # ---------------------------------------------------------------- builders

    def _tcp(
        self,
        t0: float,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        up: int,
        down: int,
        label: str = BENIGN,
        *,
        outcome: str = "complete",      # complete | refused | dropped
        kind: str = "text",
        rtt: float = 0.002,
        think: float = 0.0,             # pause between request and response
        hold: float = 0.0,              # keep the flow open this long before FIN
        close: str = "fin",             # fin | rst | none
    ) -> Iterator[Packet]:
        rng = self.rng
        t = t0
        yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP + 20, SYN, b"", label)
        if outcome == "dropped":
            return
        if outcome == "refused":
            yield Packet(t + rtt, dst, src, "tcp", dport, sport, ETH_IP_TCP, RST | ACK, b"", label)
            return
        t += rtt
        yield Packet(t, dst, src, "tcp", dport, sport, ETH_IP_TCP + 20, SYN | ACK, b"", label)
        t += rtt
        yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP, ACK, b"", label)

        # request, segmented at the MSS
        remaining = up
        while remaining > 0:
            seg = min(remaining, MSS)
            remaining -= seg
            t += rtt * rng.uniform(0.3, 1.5)
            yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP + seg, PSH | ACK,
                         _payload(seg, kind, rng), label)

        t += think if think else rtt * rng.uniform(1.0, 4.0)

        remaining = down
        while remaining > 0:
            seg = min(remaining, MSS)
            remaining -= seg
            t += rtt * rng.uniform(0.2, 1.2)
            yield Packet(t, dst, src, "tcp", dport, sport, ETH_IP_TCP + seg, PSH | ACK,
                         _payload(seg, kind, rng), label)
            if remaining > 0 and rng.random() < 0.25:
                t += rtt * 0.5  # advance the clock, never branch off it
                yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP, ACK, b"", label)

        t += hold
        if close == "fin":
            yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP, FIN | ACK, b"", label)
            yield Packet(t + rtt, dst, src, "tcp", dport, sport, ETH_IP_TCP, FIN | ACK, b"", label)
        elif close == "rst":
            yield Packet(t, src, dst, "tcp", sport, dport, ETH_IP_TCP, RST | ACK, b"", label)

    def _udp(
        self, t0: float, src: str, sport: int, dst: str, dport: int,
        up: int, down: int, label: str = BENIGN, *, kind: str = "text", rtt: float = 0.004,
    ) -> Iterator[Packet]:
        rng = self.rng
        yield Packet(t0, src, dst, "udp", sport, dport, ETH_IP_UDP + up,
                     0, _payload(up, kind, rng), label)
        if down:
            yield Packet(t0 + rtt * rng.uniform(0.5, 2.0), dst, src, "udp", dport, sport,
                         ETH_IP_UDP + down, 0, _payload(down, kind, rng), label)

    def _eph(self) -> int:
        return self.rng.randint(32768, 60999)

    # ------------------------------------------------------------ benign mixes

    def _benign(self, duration: float) -> list[Iterator[Packet]]:
        rng, net = self.rng, self.net
        gens: list[Iterator[Packet]] = []

        def poisson_times(rate: float) -> list[float]:
            times, t = [], 0.0
            while t < duration:
                t += rng.expovariate(rate) if rate > 0 else duration
                if t < duration:
                    times.append(t)
            return times

        # web browsing, internal and external
        for t in poisson_times(1.6):
            client = rng.choice(net.clients)
            if rng.random() < 0.55:
                dst, dport, rtt = net.web, rng.choice([80, 443]), rng.uniform(0.0008, 0.004)
            else:
                dst, dport, rtt = rng.choice(net.external), 443, rng.uniform(0.02, 0.11)
            gens.append(self._tcp(t, client, self._eph(), dst, dport,
                                  up=rng.randint(300, 1800), down=rng.randint(1200, 90_000),
                                  rtt=rtt, kind="text" if dport == 80 else "encrypted",
                                  think=rng.uniform(0.01, 0.4)))
        # DNS lookups
        for t in poisson_times(2.4):
            gens.append(self._udp(t, rng.choice(net.clients), self._eph(), net.dns, 53,
                                  up=rng.randint(28, 64), down=rng.randint(60, 300)))
        # internal database queries
        for t in poisson_times(0.9):
            gens.append(self._tcp(t, rng.choice(net.clients), self._eph(), net.db, 5432,
                                  up=rng.randint(80, 600), down=rng.randint(200, 12_000),
                                  rtt=rng.uniform(0.0004, 0.0015), kind="text"))
        # SMB file access
        for t in poisson_times(0.5):
            gens.append(self._tcp(t, rng.choice(net.clients), self._eph(), net.files, 445,
                                  up=rng.randint(400, 3000), down=rng.randint(2000, 400_000),
                                  rtt=rng.uniform(0.0005, 0.002), kind="encrypted"))
        # interactive SSH to a server: long, small packets, irregular
        for t in poisson_times(0.07):
            gens.append(self._interactive_ssh(t, rng.choice(net.clients), rng.choice(net.servers),
                                              dur=min(rng.uniform(20, 110), max(duration - t, 1.0))))
        # video streaming: sustained download
        for t in poisson_times(0.05):
            gens.append(self._tcp(t, rng.choice(net.clients), self._eph(), rng.choice(net.external), 443,
                                  up=rng.randint(800, 2500), down=rng.randint(2_000_000, 8_000_000),
                                  rtt=rng.uniform(0.015, 0.05), kind="encrypted"))
        # NTP + occasional ICMP keepalive to the gateway
        for t in poisson_times(0.12):
            gens.append(self._udp(t, rng.choice(net.clients), self._eph(), net.gateway, 123,
                                  up=48, down=48, kind="zeros"))
        for t in poisson_times(0.25):
            c = rng.choice(net.clients)
            gens.append(iter([
                Packet(t, c, net.gateway, "icmp", 0, 8, 98, 0, _payload(56, "zeros", rng), BENIGN),
                Packet(t + 0.001, net.gateway, c, "icmp", 0, 0, 98, 0, _payload(56, "zeros", rng), BENIGN),
            ]))
        # a small amount of legitimately odd traffic, so the model does not learn
        # that "unusual == malicious" from an unrealistically clean baseline
        for t in poisson_times(0.08):
            gens.append(self._tcp(t, rng.choice(net.clients), self._eph(), rng.choice(net.external),
                                  rng.choice([8080, 9001, 3478, 5222, 1935]),
                                  up=rng.randint(200, 4000), down=rng.randint(200, 60_000),
                                  rtt=rng.uniform(0.03, 0.14), kind="encrypted"))
        return gens

    def _interactive_ssh(self, t0: float, src: str, dst: str, dur: float) -> Iterator[Packet]:
        rng = self.rng
        sport = self._eph()
        yield from self._tcp(t0, src, sport, dst, 22, up=1200, down=1400,
                             rtt=rng.uniform(0.0006, 0.002), kind="encrypted", close="none")
        t = t0 + 0.05
        end = t0 + dur
        while t < end:
            t += rng.expovariate(2.5)
            if t >= end:
                break
            # One draw per packet, used for BOTH the frame size and the payload:
            # drawing them separately produced frames declaring fewer bytes than
            # they carried, which is physically impossible and showed up as a
            # size mismatch the moment the traffic was written to a real pcap.
            keystroke = rng.randint(36, 120)
            yield Packet(t, src, dst, "tcp", sport, 22, ETH_IP_TCP + keystroke,
                         PSH | ACK, _payload(keystroke, "encrypted", rng), BENIGN)
            t += rng.uniform(0.001, 0.02)
            echo = rng.randint(36, 900)
            yield Packet(t, dst, src, "tcp", 22, sport, ETH_IP_TCP + echo, PSH | ACK,
                         _payload(echo, "encrypted", rng), BENIGN)
        yield Packet(end, src, dst, "tcp", sport, 22, ETH_IP_TCP, FIN | ACK, b"", BENIGN)
        yield Packet(end + 0.002, dst, src, "tcp", 22, sport, ETH_IP_TCP, FIN | ACK, b"", BENIGN)

    # ----------------------------------------------------------------- attacks

    def _attack(self, spec: AttackSpec) -> list[Iterator[Packet]]:
        builder: Callable[[AttackSpec], list[Iterator[Packet]]] = {
            PORT_SCAN: self._port_scan,
            NET_SCAN: self._net_scan,
            DOS_FLOOD: self._dos_flood,
            SSH_BRUTEFORCE: self._ssh_bruteforce,
            WEB_BRUTEFORCE: self._web_bruteforce,
            SLOWLORIS: self._slowloris,
            DNS_TUNNEL: self._dns_tunnel,
            EXFILTRATION: self._exfiltration,
            C2_BEACON: self._c2_beacon,
        }[spec.family]
        return builder(spec)

    def _port_scan(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """nmap -sS: one target, hundreds of ports, no handshake completed."""
        rng, net = self.rng, self.net
        attacker = rng.choice(net.attackers)
        target = rng.choice(net.servers)
        rotate = s.stealth  # spread the scan over several sources to dilute fan-out
        open_ports = {22, 80, 443, 445, 5432, 53}
        rate = 45.0 * s.intensity * (STEALTH_RATE[PORT_SCAN] if s.stealth else 1.0)
        n = max(int(s.duration * rate), 8)
        ports = rng.sample(range(1, 9000), min(n, 8999))
        gens = []
        for i, port in enumerate(ports):
            t = s.start + i / rate + rng.uniform(0, 0.004)
            outcome = "complete" if port in open_ports else ("refused" if rng.random() < 0.75 else "dropped")
            src = rng.choice(net.attackers) if rotate else attacker
            gens.append(self._tcp(t, src, self._eph(), target, port, up=0, down=0,
                                  label=PORT_SCAN, outcome=outcome, close="rst",
                                  rtt=rng.uniform(0.001, 0.01)))
        return gens

    def _net_scan(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Host discovery sweep across the subnet on a handful of ports."""
        rng, net = self.rng, self.net
        attacker = rng.choice(net.attackers + [net.compromised])
        rate = 25.0 * s.intensity * (STEALTH_RATE[NET_SCAN] if s.stealth else 1.0)
        gens, i = [], 0
        live = set(net.clients[:25]) | set(net.servers)
        while i / rate < s.duration:
            host = f"192.168.1.{(i % 254) + 1}"
            for port in (445, 22, 3389):
                t = s.start + i / rate + rng.uniform(0, 0.01)
                outcome = "complete" if (host in live and port == 445) else (
                    "refused" if host in live else "dropped")
                gens.append(self._tcp(t, attacker, self._eph(), host, port, up=0, down=0,
                                      label=NET_SCAN, outcome=outcome, close="rst",
                                      rtt=rng.uniform(0.001, 0.02)))
            i += 1
        return gens

    def _dos_flood(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """SYN flood from a small botnet, with spoofed source addresses.

        Each individual source looks almost idle - this is the case the
        destination-side features exist for.
        """
        rng, net = self.rng, self.net
        target = net.web
        rate = 220.0 * s.intensity * (STEALTH_RATE[DOS_FLOOD] if s.stealth else 1.0)
        bots = [f"{rng.randint(11, 223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                for _ in range(max(int(40 * s.intensity), 12))]
        gens, i = [], 0
        while i / rate < s.duration:
            t = s.start + i / rate
            bot = bots[i % len(bots)]
            gens.append(self._tcp(t, bot, self._eph(), target, rng.choice([80, 443]),
                                  up=0, down=0, label=DOS_FLOOD, outcome="dropped",
                                  close="none", rtt=0.001))
            i += 1
        return gens

    def _ssh_bruteforce(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """hydra against sshd: full handshake, auth fails, connection reset."""
        rng, net = self.rng, self.net
        attacker = rng.choice(net.attackers)
        target = rng.choice([net.web, net.files])
        rate = 9.0 * s.intensity * (STEALTH_RATE[SSH_BRUTEFORCE] if s.stealth else 1.0)
        gens, i = [], 0
        while i / rate < s.duration:
            t = s.start + i / rate + rng.uniform(0, 0.05)
            success = rng.random() < 0.004
            gens.append(self._tcp(t, attacker, self._eph(), target, 22,
                                  up=rng.randint(900, 1500), down=rng.randint(900, 1600),
                                  label=SSH_BRUTEFORCE, kind="encrypted",
                                  rtt=rng.uniform(0.02, 0.09),
                                  close="fin" if success else "rst",
                                  think=rng.uniform(0.05, 0.3)))
            i += 1
        return gens

    def _web_bruteforce(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Credential stuffing on POST /login: identical small requests, 401 back."""
        rng, net = self.rng, self.net
        attacker = rng.choice(net.attackers)
        rate = 14.0 * s.intensity * (STEALTH_RATE[WEB_BRUTEFORCE] if s.stealth else 1.0)
        gens, i = [], 0
        while i / rate < s.duration:
            t = s.start + i / rate + rng.uniform(0, 0.03)
            # a careful attacker varies request size, breaking the
            # "identical requests" tell that makes loud brute force trivial
            spread = (300, 1400) if s.stealth else (380, 460)
            gens.append(self._tcp(t, attacker, self._eph(), net.web, 80,
                                  up=rng.randint(*spread), down=rng.randint(240, 900),
                                  label=WEB_BRUTEFORCE, kind="text",
                                  rtt=rng.uniform(0.02, 0.08), close="rst",
                                  think=rng.uniform(0.01, 0.06)))
            i += 1
        return gens

    def _slowloris(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Many sockets held open with trickled partial headers."""
        rng, net = self.rng, self.net
        attacker = rng.choice(net.attackers)
        n_sockets = max(int(120 * s.intensity * (0.15 if s.stealth else 1.0)), 8)
        gens = []
        for i in range(n_sockets):
            t0 = s.start + i * (s.duration * 0.25 / n_sockets)
            gens.append(self._trickle(t0, attacker, net.web, min(s.duration, 300.0)))
        return gens

    def _trickle(self, t0: float, src: str, dst: str, dur: float) -> Iterator[Packet]:
        rng = self.rng
        sport = self._eph()
        rtt = rng.uniform(0.02, 0.07)
        yield Packet(t0, src, dst, "tcp", sport, 80, ETH_IP_TCP + 20, SYN, b"", SLOWLORIS)
        yield Packet(t0 + rtt, dst, src, "tcp", 80, sport, ETH_IP_TCP + 20, SYN | ACK, b"", SLOWLORIS)
        yield Packet(t0 + 2 * rtt, src, dst, "tcp", sport, 80, ETH_IP_TCP, ACK, b"", SLOWLORIS)
        t = t0 + 2 * rtt
        end = t0 + dur
        while t < end:
            t += rng.uniform(9.0, 14.0)
            if t >= end:
                break
            n = rng.randint(18, 34)
            yield Packet(t, src, dst, "tcp", sport, 80, ETH_IP_TCP + n, PSH | ACK,
                         _payload(n, "text", rng), SLOWLORIS)

    def _dns_tunnel(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Data smuggled in oversized, high-entropy DNS labels at a steady rate."""
        rng, net = self.rng, self.net
        src = net.compromised
        rate = 11.0 * s.intensity * (STEALTH_RATE[DNS_TUNNEL] if s.stealth else 1.0)
        gens, i = [], 0
        while i / rate < s.duration:
            t = s.start + i / rate + rng.uniform(0, 0.01)
            gens.append(self._udp(t, src, self._eph(), net.dns, 53,
                                  up=rng.randint(180, 280), down=rng.randint(200, 420),
                                  label=DNS_TUNNEL, kind="base32", rtt=rng.uniform(0.01, 0.04)))
            i += 1
        return gens

    def _exfiltration(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Large encrypted upload from an internal host to an unusual external port."""
        rng, net = self.rng, self.net
        gens = []
        chunks = max(int(s.duration / (4 if s.stealth else 10)), 2)  # staged upload
        for i in range(chunks):
            t = s.start + i * (s.duration / chunks)
            gens.append(self._tcp(t, net.compromised, self._eph(), net.c2,
                                  rng.choice([8443, 4444, 9090, 31337]),
                                  up=int(rng.randint(1_500_000, 9_000_000) * s.intensity
                                         * (0.035 if s.stealth else 1.0)),
                                  down=rng.randint(400, 2500),
                                  label=EXFILTRATION, kind="encrypted",
                                  rtt=rng.uniform(0.04, 0.12)))
        return gens

    def _c2_beacon(self, s: AttackSpec) -> list[Iterator[Packet]]:
        """Implant check-in on a fixed timer with low jitter - periodicity is the tell."""
        rng, net = self.rng, self.net
        period = max((110.0 if s.stealth else 14.0) / max(s.intensity, 0.2), 5.0)
        gens, t = [], s.start
        while t < s.start + s.duration:
            gens.append(self._tcp(t, net.compromised, self._eph(), net.c2, 443,
                                  up=rng.randint(240, 320), down=rng.randint(180, 420),
                                  label=C2_BEACON, kind="encrypted",
                                  rtt=rng.uniform(0.05, 0.1), close="fin"))
            jitter = 0.25 if s.stealth else 0.04  # a careful implant jitters more
            t += period * rng.uniform(1 - jitter, 1 + jitter)
        return gens

    # ------------------------------------------------------------------ public

    def plan(self, duration: float, families: tuple[str, ...] = ATTACK_FAMILIES,
             density: float = 1.0, stealth_ratio: float = 0.0) -> list[AttackSpec]:
        """Schedule attack windows across the capture, avoiding full overlap."""
        rng = self.rng
        specs: list[AttackSpec] = []
        for family in families:
            lo, hi, per_10min = WINDOW_PROFILE.get(family, _DEFAULT_WINDOW)
            if stealth_ratio > 0:
                # being slow only works if there is time to be slow in
                hi = max(hi, min(duration * 0.8, hi * 3))
            n = max(1, int(round(density * per_10min * duration / 600)))
            for _ in range(n):
                dur = min(rng.uniform(lo, hi), duration * 0.85)
                start = rng.uniform(1.0, max(duration - dur - 1.0, 2.0))
                specs.append(AttackSpec(family, start, dur, rng.uniform(0.6, 1.4),
                                        stealth=rng.random() < stealth_ratio))
        return sorted(specs, key=lambda s: s.start)

    def generate(self, duration: float, attacks: list[AttackSpec] | None = None,
                 benign: bool = True) -> Iterator[Packet]:
        """Merge every scheduled session into one timestamp-ordered stream."""
        gens: list[Iterator[Packet]] = []
        if benign:
            gens += self._benign(duration)
        for spec in attacks or []:
            gens += self._attack(spec)
        return _merge(gens)


def _monotonic(gen: Iterator[Packet]) -> Iterator[Packet]:
    """Guarantee a session's own packets are non-decreasing in time.

    The k-way merge below is only correct if each input stream is ordered. This
    guard makes that invariant structural instead of a convention every session
    builder has to remember.
    """
    last = float("-inf")
    for pkt in gen:
        if pkt.ts < last:
            pkt.ts = last
        last = pkt.ts
        yield pkt


def _merge(gens: list[Iterator[Packet]]) -> Iterator[Packet]:
    """K-way merge of ordered packet streams. O(log k) per packet, O(k) memory."""
    heap: list[tuple[float, int, Packet, Iterator[Packet]]] = []
    gens = [_monotonic(g) for g in gens]
    for i, g in enumerate(gens):
        for pkt in g:
            heapq.heappush(heap, (pkt.ts, i, pkt, g))
            break
    while heap:
        _, i, pkt, g = heapq.heappop(heap)
        yield pkt
        for nxt in g:
            heapq.heappush(heap, (nxt.ts, i, nxt, g))
            break
