"""Training and evaluation.

The protocol, stated explicitly because it is what makes the numbers mean
something:

1. Stage A is fitted on **benign-only** captures. It never sees an attack.
2. Stage B is fitted on labelled mixed captures, class-capped so one flood does
   not become 70% of the training set.
3. Evaluation uses **different seeds** - different simulated days. No flow from a
   training capture appears in a test capture.
4. The operating point is measured by replaying test captures through the real
   `Engine`, with adaptive thresholds, warmed up on a benign capture first (as a
   deployed sensor would be). Not by thresholding a score column offline.
5. False positives are measured on benign-only test captures, in alerts/hour,
   because "precision" on an attack-heavy capture flatters a detector.
6. Detection latency is measured from the start of each attack window to the
   first alert carrying that ground truth - and it includes the flow export
   delay, because that delay is real.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score,
)

from aegis.config import settings
from aegis.core.engine import Engine
from aegis.core.types import Verdict
from aegis.ml.dataset import Capture, balance, simulate_capture, stack, vectorize_many
from aegis.ml.model import DetectionModel
from aegis.ml.threshold import AdaptiveThreshold
from aegis.sources.lab import ALL_CLASSES, ATTACK_FAMILIES, BENIGN

Progress = Callable[[str], None]

CLASS_CAP = 2500


@dataclass
class Evaluation:
    pr_auc: float = 0.0
    roc_auc: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    benign_alerts_per_hour: float = 0.0
    benign_incidents_per_hour: float = 0.0
    benign_fp_rate: float = 0.0
    benign_flows: int = 0
    hosts_threshold_raised: int = 0
    family_recall: dict[str, float] = field(default_factory=dict)
    family_support: dict[str, int] = field(default_factory=dict)
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_by_family: dict[str, float] = field(default_factory=dict)
    classifier_macro_f1: float = 0.0
    classifier_report: dict[str, dict[str, float]] = field(default_factory=dict)
    confusion: dict[str, Any] = field(default_factory=dict)
    throughput_pkts_per_sec: float = 0.0
    incidents: int = 0
    alerts: int = 0
    #: the same evaluation re-run against low-and-slow attack variants
    stealth: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


def _is_attack(labels: np.ndarray) -> np.ndarray:
    return labels != BENIGN


def train_and_evaluate(
    train_seeds: list[int],
    test_seeds: list[int],
    duration: float = 600.0,
    density: float = 1.0,
    progress: Progress = print,
) -> tuple[DetectionModel, Evaluation]:
    t_start = time.time()

    # ---- 1. benign captures for stage A -------------------------------------
    progress(f"[1/6] Captures bénignes d'entraînement ({len(train_seeds)} x {duration:.0f}s)...")
    benign_train = [simulate_capture(s * 31 + 7, duration, benign_only=True) for s in train_seeds]
    X_benign, _ = stack(benign_train)
    progress(f"      {len(X_benign):,} flux bénins")

    model = DetectionModel()
    progress("[2/6] Entraînement étage A (IsolationForest) + calibration ECDF...")
    model.fit_stage_a(X_benign)

    # ---- 2. labelled captures for stage B -----------------------------------
    progress(f"[3/6] Captures mixtes d'entraînement ({len(train_seeds)} x {duration:.0f}s)...")
    mixed_train = [simulate_capture(s, duration, density=density) for s in train_seeds]
    X_mixed, y_mixed = stack(mixed_train)
    rng = np.random.default_rng(0)
    Xb, yb = balance(X_mixed, y_mixed, CLASS_CAP, rng)
    counts = {c: int((yb == c).sum()) for c in sorted(set(yb))}
    progress(f"      {len(X_mixed):,} flux -> {len(Xb):,} après plafonnement par classe")
    progress(f"      {counts}")
    progress("[4/6] Entraînement étage B (HistGradientBoosting multi-classes)...")
    model.fit_stage_b(Xb, yb)

    # ---- 3. evaluation on held-out captures ---------------------------------
    progress(f"[5/6] Évaluation « bruyante » sur {len(test_seeds)} captures de test (seeds disjoints)...")
    ev = evaluate(model, test_seeds, duration, density, progress=progress)
    progress("      Évaluation « furtive » (variantes lentes et discrètes)...")
    stealth_ev = evaluate(model, test_seeds, duration, density, stealth_ratio=1.0, progress=progress)
    ev.stealth = {
        "precision": stealth_ev.precision,
        "recall": stealth_ev.recall,
        "f1": stealth_ev.f1,
        "pr_auc": stealth_ev.pr_auc,
        "family_recall": stealth_ev.family_recall,
        "family_support": stealth_ev.family_support,
        "classifier_macro_f1": stealth_ev.classifier_macro_f1,
        "latency_p50": stealth_ev.latency_p50,
        "latency_p95": stealth_ev.latency_p95,
        "incidents": stealth_ev.incidents,
        "alerts": stealth_ev.alerts,
    }

    model.meta.trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    model.meta.train_seeds = train_seeds
    model.meta.test_seeds = test_seeds
    model.meta.metrics = ev.as_dict()
    model.meta.notes = (
        f"stage A: benign-only ({len(X_benign)} flows); stage B: {len(Xb)} flows capped at "
        f"{CLASS_CAP}/class; split by capture seed; operating point measured through Engine"
    )
    progress(f"[6/6] Terminé en {time.time() - t_start:.1f}s")
    return model, ev


def evaluate(model: DetectionModel, test_seeds: list[int], duration: float = 600.0,
             density: float = 1.0, stealth_ratio: float = 0.0,
             progress: Progress = print) -> Evaluation:
    ev = Evaluation()

    benign_test = [simulate_capture(s * 31 + 7, duration, benign_only=True) for s in test_seeds]
    mixed_test = [simulate_capture(s, duration, density=density, stealth_ratio=stealth_ratio)
                  for s in test_seeds]

    # --- threshold-free ranking quality -------------------------------------
    X_test, y_test = stack(mixed_test)
    Xb_test, yb_test = stack(benign_test)
    X_all = np.vstack([X_test, Xb_test])
    y_all = np.concatenate([y_test, yb_test])
    scores_all = model.score(X_all)
    truth_all = _is_attack(y_all)
    if truth_all.any() and not truth_all.all():
        ev.pr_auc = float(average_precision_score(truth_all, scores_all))
        ev.roc_auc = float(roc_auc_score(truth_all, scores_all))

    # --- operating point, replayed through the real engine -------------------
    tp = fp = fn = tn = 0
    fam_hits: dict[str, int] = {}
    fam_total: dict[str, int] = {}
    latencies: list[float] = []
    lat_by_fam: dict[str, list[float]] = {}
    total_packets = 0
    t0 = time.time()
    incidents = 0
    alerts = 0

    for benign_cap, mixed_cap in zip(benign_test, mixed_test):
        engine = Engine(model, thresholds=AdaptiveThreshold(), explain=False)
        # Warm the per-host baselines on benign traffic, as a deployed sensor is.
        _benign_verdicts = _replay(engine, benign_cap)
        bstats = engine.stats
        ev.benign_flows += bstats.flows
        ev.benign_alerts_per_hour += bstats.alerts_per_hour
        ev.benign_fp_rate += bstats.alerts / max(bstats.flows, 1)
        # The number an analyst actually lives with is incidents per hour, not
        # alerts per hour: correlation collapses a burst into one row of work.
        benign_verdicts = [v for v in _benign_verdicts if v.is_alert]
        ev.benign_incidents_per_hour += (
            _count_incidents(benign_verdicts) / (bstats.span / 3600.0) if bstats.span > 0 else 0.0
        )
        ev.hosts_threshold_raised += sum(
            1 for row in engine.thresholds.snapshot(limit=10_000)
            if row["calibrated"] and bool(row["raised"])
        )

        verdicts = _replay(engine, mixed_cap)
        total_packets += engine.stats.packets
        alerts += sum(1 for v in verdicts if v.is_alert)

        first_alert_ts: dict[str, float] = {}
        for v in verdicts:
            truth = v.flow.label
            attack = truth != BENIGN
            if attack:
                fam_total[truth] = fam_total.get(truth, 0) + 1
            if v.is_alert and attack:
                tp += 1
                fam_hits[truth] = fam_hits.get(truth, 0) + 1
                # the export clock, not the last-packet clock: an analyst cannot
                # see a flow before the assembler has let go of it
                first_alert_ts.setdefault(truth, v.flow.export_ts or v.flow.end_ts)
            elif v.is_alert and not attack:
                fp += 1
            elif not v.is_alert and attack:
                fn += 1
            else:
                tn += 1

        for spec in mixed_cap.attacks:
            got = first_alert_ts.get(spec.family)
            if got is not None and got >= spec.start:
                lat = got - spec.start
                latencies.append(lat)
                lat_by_fam.setdefault(spec.family, []).append(lat)

        incidents += _count_incidents(verdicts)

    n = max(len(test_seeds), 1)
    ev.tp, ev.fp, ev.fn, ev.tn = tp, fp, fn, tn
    ev.precision = tp / (tp + fp) if (tp + fp) else 0.0
    ev.recall = tp / (tp + fn) if (tp + fn) else 0.0
    ev.f1 = (2 * ev.precision * ev.recall / (ev.precision + ev.recall)
             if (ev.precision + ev.recall) else 0.0)
    ev.benign_alerts_per_hour /= n
    ev.benign_incidents_per_hour /= n
    ev.benign_fp_rate /= n
    ev.family_recall = {f: round(fam_hits.get(f, 0) / t, 4) for f, t in sorted(fam_total.items())}
    ev.family_support = dict(sorted(fam_total.items()))
    if latencies:
        ev.latency_p50 = float(np.percentile(latencies, 50))
        ev.latency_p95 = float(np.percentile(latencies, 95))
    ev.latency_by_family = {f: round(float(np.median(v)), 2) for f, v in sorted(lat_by_fam.items())}
    ev.throughput_pkts_per_sec = total_packets / max(time.time() - t0, 1e-6)
    ev.incidents = incidents
    ev.alerts = alerts

    # --- stage B: family naming quality on true attack flows -----------------
    attack_mask = _is_attack(y_test)
    if attack_mask.any():
        fam_pred, _ = model.classify(X_test[attack_mask])
        y_true = y_test[attack_mask].astype(str)
        labels = [f for f in ATTACK_FAMILIES if f in set(y_true) | set(fam_pred)]
        p, r, f1, support = precision_recall_fscore_support(
            y_true, fam_pred.astype(str), labels=labels, zero_division=0,
        )
        ev.classifier_report = {
            lbl: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                  "f1": round(float(f1[i]), 4), "support": int(support[i])}
            for i, lbl in enumerate(labels)
        }
        ev.classifier_macro_f1 = float(np.mean(f1)) if len(f1) else 0.0
        cm_labels = labels + ["UNKNOWN", BENIGN]
        cm = confusion_matrix(y_true, fam_pred.astype(str), labels=cm_labels)
        ev.confusion = {"labels": cm_labels, "matrix": cm.tolist()}

    progress(f"      PR-AUC {ev.pr_auc:.4f} | rappel {ev.recall:.4f} | précision {ev.precision:.4f} "
             f"| FP {ev.benign_alerts_per_hour:.0f} alertes/h -> {ev.benign_incidents_per_hour:.1f} "
             f"incidents/h | latence p50 {ev.latency_p50:.1f}s")
    return ev


def _replay(engine: Engine, capture: Capture) -> list[Verdict]:
    """Score a pre-computed capture's flows in order, in engine-sized batches."""
    verdicts: list[Verdict] = []
    batch: list = []
    for flow in capture.flows:
        batch.append(flow)
        if len(batch) >= 512:
            verdicts.extend(engine.score_flows(batch))
            batch = []
    if batch:
        verdicts.extend(engine.score_flows(batch))
    engine.stats.packets += sum(f.packets for f in capture.flows)
    # The engine normally learns the capture span from `feed_packet`; replaying
    # pre-computed flows bypasses that, and without it alerts/hour divides by a
    # zero span and silently reports 0.
    if capture.flows:
        engine.stats.first_ts = min(engine.stats.first_ts or capture.flows[0].start_ts,
                                    capture.flows[0].start_ts)
        engine.stats.last_ts = max(engine.stats.last_ts, max(f.end_ts for f in capture.flows))
    return verdicts


def _count_incidents(verdicts: list[Verdict]) -> int:
    from aegis.core.correlate import Correlator

    corr = Correlator()
    base = datetime.now(timezone.utc)
    from datetime import timedelta

    for v in verdicts:
        if v.is_alert:
            corr.ingest(v, base + timedelta(seconds=v.flow.end_ts))
    return corr.incidents_opened
