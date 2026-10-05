"""Dataset construction.

A capture is one simulated period of network life, identified by its seed. The
train/test split is **by capture**, never by row.

That choice is the single most important methodological decision here. Flows from
the same attack burst are highly correlated; a random row split puts siblings of
a test flow into the training set and yields the 99.9% accuracy that this kind of
project is famous for and that collapses on contact with real traffic. Splitting
by capture forces the model to generalise to an attack burst it has never seen.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from aegis.config import settings
from aegis.core.features import FEATURE_NAMES
from aegis.core.flows import FlowTable
from aegis.core.types import Flow
from aegis.sources.lab import ATTACK_FAMILIES, BENIGN, LabNetwork

#: Values above this are clipped; byte counters can otherwise reach 1e9 and
#: dominate the scaler while carrying no extra information.
CLIP_HI = 1e9


def vectorize(flow: Flow) -> np.ndarray:
    """Flow -> feature vector, in `FEATURE_NAMES` order, finite and clipped."""
    vec = np.empty(len(FEATURE_NAMES), dtype=np.float32)
    feats = flow.features
    for i, name in enumerate(FEATURE_NAMES):
        vec[i] = feats.get(name, 0.0)
    np.nan_to_num(vec, copy=False, nan=0.0, posinf=CLIP_HI, neginf=-CLIP_HI)
    return np.clip(vec, -CLIP_HI, CLIP_HI, out=vec)


def vectorize_many(flows: list[Flow]) -> np.ndarray:
    if not flows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
    return np.vstack([vectorize(f) for f in flows])


@dataclass(slots=True)
class Capture:
    """One simulated period, with its flows and labels."""

    seed: int
    duration: float
    flows: list[Flow] = field(default_factory=list)
    attacks: list = field(default_factory=list)   # list[AttackSpec], for latency metrics

    @property
    def X(self) -> np.ndarray:
        return vectorize_many(self.flows)

    @property
    def y(self) -> np.ndarray:
        return np.array([f.label for f in self.flows], dtype=object)


def simulate_capture(seed: int, duration: float = 600.0, *, benign_only: bool = False,
                     density: float = 1.0, stealth_ratio: float = 0.0,
                     families: tuple[str, ...] = ATTACK_FAMILIES) -> Capture:
    """Run one capture through the real packet -> flow -> feature pipeline."""
    net = LabNetwork(seed=seed)
    attacks = [] if benign_only else net.plan(
        duration, families=families, density=density, stealth_ratio=stealth_ratio)
    table = FlowTable()
    flows = list(table.feed(net.generate(duration, attacks)))
    return Capture(seed=seed, duration=duration, flows=flows, attacks=attacks)


def build_corpus(train_seeds: list[int], test_seeds: list[int], duration: float = 600.0,
                 density: float = 1.0) -> dict[str, object]:
    """Build the full training corpus: benign-only + mixed captures, split by seed."""
    out: dict[str, object] = {}
    for split, seeds in (("train", train_seeds), ("test", test_seeds)):
        benign_caps = [simulate_capture(s * 31 + 7, duration, benign_only=True) for s in seeds]
        mixed_caps = [simulate_capture(s, duration, density=density) for s in seeds]
        out[f"{split}_benign"] = benign_caps
        out[f"{split}_mixed"] = mixed_caps
    return out


def stack(captures: list[Capture]) -> tuple[np.ndarray, np.ndarray]:
    Xs = [c.X for c in captures if c.flows]
    ys = [c.y for c in captures if c.flows]
    if not Xs:
        return np.empty((0, len(FEATURE_NAMES)), np.float32), np.empty((0,), object)
    return np.vstack(Xs), np.concatenate(ys)


def balance(X: np.ndarray, y: np.ndarray, cap: int, rng: np.random.Generator) -> tuple[np.ndarray, np.ndarray]:
    """Cap every class at `cap` rows.

    A single SYN flood produces thousands of near-identical flows. Left alone it
    would be 70% of the training set and the model would learn little else; the
    cap keeps the rare families (beacon, exfiltration) visible.
    """
    keep: list[np.ndarray] = []
    for cls in np.unique(y):
        idx = np.flatnonzero(y == cls)
        if len(idx) > cap:
            idx = rng.choice(idx, cap, replace=False)
        keep.append(idx)
    sel = np.concatenate(keep)
    rng.shuffle(sel)
    return X[sel], y[sel]


def save_npz(path: Path, X: np.ndarray, y: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, X=X, y=y.astype("U24"), features=np.array(FEATURE_NAMES))


def load_npz(path: Path) -> tuple[np.ndarray, np.ndarray]:
    data = np.load(path, allow_pickle=False)
    stored = tuple(str(f) for f in data["features"])
    if stored != FEATURE_NAMES:
        raise ValueError(
            f"dataset {path.name} was built with a different feature set "
            f"({len(stored)} columns vs {len(FEATURE_NAMES)}); rebuild it with `aegis dataset`"
        )
    return data["X"], data["y"].astype(object)


__all__ = [
    "ATTACK_FAMILIES", "BENIGN", "Capture", "balance", "build_corpus", "load_npz",
    "save_npz", "simulate_capture", "stack", "vectorize", "vectorize_many",
    "settings",
]
