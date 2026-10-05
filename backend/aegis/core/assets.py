"""Asset inventory: what a machine is worth.

Severity cannot be a function of the anomaly score alone. A port scan of a
printer and a port scan of the database server produce the same score and must
not produce the same severity. Criticality (1 = negligible, 5 = critical) is
what turns a score into a priority.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(slots=True)
class Asset:
    cidr: str
    name: str
    criticality: int = 3
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.criticality = max(1, min(5, int(self.criticality)))


#: Shipped defaults match the lab topology; editable from the Settings view.
DEFAULT_ASSETS: list[Asset] = [
    Asset("192.168.1.10/32", "Serveur web", 5, ["web", "production"]),
    Asset("192.168.1.11/32", "Base de données", 5, ["db", "production"]),
    Asset("192.168.1.12/32", "Serveur DNS", 4, ["dns", "infra"]),
    Asset("192.168.1.13/32", "Serveur de fichiers", 4, ["smb", "data"]),
    Asset("192.168.1.1/32", "Passerelle", 4, ["network"]),
    Asset("192.168.1.0/24", "Poste de travail", 2, ["lan", "endpoint"]),
    Asset("10.0.0.0/8", "Réseau interne", 3, ["lan"]),
    Asset("0.0.0.0/0", "Hôte externe", 1, ["external"]),
]


class AssetRegistry:
    """Longest-prefix lookup over the inventory."""

    def __init__(self, assets: list[Asset] | None = None) -> None:
        self._entries: list[tuple[ipaddress.IPv4Network, Asset]] = []
        for asset in assets if assets is not None else DEFAULT_ASSETS:
            self.add(asset)

    def add(self, asset: Asset) -> None:
        try:
            net = ipaddress.ip_network(asset.cidr, strict=False)
        except ValueError:
            return
        if isinstance(net, ipaddress.IPv4Network):
            self._entries.append((net, asset))
            # longest prefix first, so /32 wins over /24 wins over /0
            self._entries.sort(key=lambda e: e[0].prefixlen, reverse=True)

    def lookup(self, ip: str) -> Asset:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return Asset("0.0.0.0/0", "Inconnu", 1)
        for net, asset in self._entries:
            if addr in net:
                return asset
        return Asset("0.0.0.0/0", "Inconnu", 1)

    def criticality(self, ip: str) -> int:
        return self.lookup(ip).criticality

    def all(self) -> list[Asset]:
        return [a for _, a in self._entries]
