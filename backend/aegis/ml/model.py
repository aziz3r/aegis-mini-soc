"""The detection model: two stages, one calibrator, one explainer.

Stage A - unsupervised anomaly detection (IsolationForest)
    Trained on *benign traffic only*, so it does not need to have seen an attack
    to flag one. This is the part that can catch something new.

Stage B - supervised family classifier (HistGradientBoosting)
    Trained on labelled traffic. It does not decide *whether* to alert; it names
    what the anomaly looks like, with a confidence. Below
    `supervised_min_confidence` it declines to name anything and returns UNKNOWN,
    because a confident wrong label is worse for an analyst than no label.

Calibration
    IsolationForest emits an unbounded, un-interpretable score. It is mapped
    through the empirical CDF of the *benign* training scores, so the number the
    analyst sees has a precise meaning: 0.97 = "more anomalous than 97% of known
    normal traffic". A fixed 0.8 threshold on a raw score means nothing; a
    threshold on this does.

Explanation
    Occlusion attribution: each feature in turn is replaced by its benign median
    and the flow re-scored. The drop in anomaly score is that feature's
    contribution. It is the same intuition SHAP formalises, computed exactly for
    one-feature subsets, in a single batched call, with no extra dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from aegis.config import settings
from aegis.core.features import FEATURE_NAMES, label_for
from aegis.core.types import Contribution

MODEL_FORMAT = 3
_CAL_POINTS = 2001
_CAL_MAX_P = 0.999


class EcdfCalibrator:
    """Maps raw anomaly scores to a benign-percentile probability in [0, 1)."""

    def __init__(self) -> None:
        self.grid: np.ndarray | None = None
        self.probs: np.ndarray | None = None
        self.tail_scale: float = 1.0

    def fit(self, raw_benign: np.ndarray) -> "EcdfCalibrator":
        probs = np.linspace(0.0, _CAL_MAX_P, _CAL_POINTS)
        grid = np.quantile(raw_benign, probs)
        # quantiles must be strictly increasing for np.interp to behave
        grid = np.maximum.accumulate(grid)
        eps = np.arange(len(grid)) * 1e-12
        self.grid, self.probs = grid + eps, probs
        spread = float(grid[-1] - np.quantile(raw_benign, 0.5)) or 1.0
        self.tail_scale = max(spread, 1e-6)
        return self

    def transform(self, raw: np.ndarray) -> np.ndarray:
        if self.grid is None or self.probs is None:
            raise RuntimeError("calibrator not fitted")
        raw = np.asarray(raw, dtype=np.float64)
        out = np.interp(raw, self.grid, self.probs)
        # Beyond everything seen in benign traffic, keep ranking rather than
        # saturating: approach 1.0 asymptotically instead of flattening at it.
        over = raw > self.grid[-1]
        if np.any(over):
            excess = (raw[over] - self.grid[-1]) / self.tail_scale
            out[over] = 1.0 - (1.0 - _CAL_MAX_P) * np.exp(-excess)
        return np.clip(out, 0.0, 1.0 - 1e-9)


@dataclass
class ModelMeta:
    trained_at: str = ""
    train_flows_benign: int = 0
    train_flows_labelled: int = 0
    train_seeds: list[int] | None = None
    test_seeds: list[int] | None = None
    classes: list[str] | None = None
    metrics: dict[str, Any] | None = None
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "trained_at": self.trained_at,
            "train_flows_benign": self.train_flows_benign,
            "train_flows_labelled": self.train_flows_labelled,
            "train_seeds": self.train_seeds or [],
            "test_seeds": self.test_seeds or [],
            "classes": self.classes or [],
            "metrics": self.metrics or {},
            "notes": self.notes,
            "format": MODEL_FORMAT,
            "features": list(FEATURE_NAMES),
        }


class DetectionModel:
    """Container for both stages plus everything needed to serve them."""

    def __init__(self) -> None:
        self.stage_a: Pipeline | None = None
        self.calibrator = EcdfCalibrator()
        self.stage_b: Pipeline | None = None
        self.baseline_median: np.ndarray | None = None
        self.meta = ModelMeta()

    # -- training -------------------------------------------------------------

    def fit_stage_a(self, X_benign: np.ndarray, *, n_estimators: int = 220,
                    contamination: float = 0.02, seed: int = 0) -> None:
        """Fit the anomaly detector on benign traffic and calibrate on it.

        `contamination` is deliberately non-zero: a real "benign" capture always
        contains a little genuine weirdness, and letting the forest carve a small
        fraction off keeps the calibration curve from being dragged by outliers.
        """
        self.stage_a = Pipeline([
            ("scale", RobustScaler(quantile_range=(5.0, 95.0))),
            ("iforest", IsolationForest(
                n_estimators=n_estimators,
                max_samples=min(4096, len(X_benign)),
                contamination=contamination,
                random_state=seed,
                n_jobs=-1,
            )),
        ])
        self.stage_a.fit(X_benign)
        self.calibrator.fit(self._raw(X_benign))
        self.baseline_median = np.median(X_benign, axis=0).astype(np.float32)
        self.meta.train_flows_benign = int(len(X_benign))

    def fit_stage_b(self, X: np.ndarray, y: np.ndarray, *, seed: int = 0) -> None:
        self.stage_b = Pipeline([
            ("clf", HistGradientBoostingClassifier(
                max_iter=300,
                learning_rate=0.09,
                max_leaf_nodes=31,
                l2_regularization=1.0,
                early_stopping=True,
                validation_fraction=0.15,
                class_weight="balanced",
                random_state=seed,
            )),
        ])
        self.stage_b.fit(X, y)
        self.meta.train_flows_labelled = int(len(X))
        self.meta.classes = sorted({str(c) for c in y})

    # -- inference ------------------------------------------------------------

    def _raw(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous (sklearn's score_samples is the inverse)."""
        assert self.stage_a is not None
        return -self.stage_a.named_steps["iforest"].score_samples(
            self.stage_a.named_steps["scale"].transform(X)
        )

    def score(self, X: np.ndarray) -> np.ndarray:
        """Calibrated anomaly probability per row, in [0, 1)."""
        return self.calibrator.transform(self._raw(X))

    def classify(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """(family, confidence) per row; UNKNOWN below the confidence floor."""
        if self.stage_b is None:
            n = len(X)
            return np.array(["UNKNOWN"] * n, dtype=object), np.zeros(n)
        proba = self.stage_b.predict_proba(X)
        classes = self.stage_b.named_steps["clf"].classes_
        best = proba.argmax(axis=1)
        conf = proba[np.arange(len(X)), best]
        families = np.array([str(classes[i]) for i in best], dtype=object)
        families[conf < settings.supervised_min_confidence] = "UNKNOWN"
        return families, conf

    def explain(self, x: np.ndarray, top: int = 4) -> list[Contribution]:
        """Occlusion attribution for one flow: which features drove the score."""
        if self.stage_a is None or self.baseline_median is None:
            return []
        x = np.asarray(x, dtype=np.float32).reshape(1, -1)
        base_raw = float(self._raw(x)[0])

        n_feat = x.shape[1]
        perturbed = np.repeat(x, n_feat, axis=0)
        perturbed[np.arange(n_feat), np.arange(n_feat)] = self.baseline_median
        occluded = self._raw(perturbed)                     # one batched call
        deltas = base_raw - occluded                        # >0 = feature raised the score

        total = float(deltas[deltas > 0].sum()) or 1.0
        order = np.argsort(-deltas)[:top]
        out: list[Contribution] = []
        for i in order:
            if deltas[i] <= 1e-9:
                continue
            value, baseline = float(x[0, i]), float(self.baseline_median[i])
            out.append(Contribution(
                feature=label_for(FEATURE_NAMES[i]),
                value=value,
                baseline=baseline,
                impact=float(deltas[i]) / total,
                direction="above" if value >= baseline else "below",
            ))
        return out

    # -- persistence ----------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return self.stage_a is not None and self.calibrator.grid is not None

    def save(self, path: Path | None = None) -> Path:
        path = path or settings.stage_a_path
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "format": MODEL_FORMAT,
            "features": list(FEATURE_NAMES),
            "stage_a": self.stage_a,
            "calibrator": {"grid": self.calibrator.grid, "probs": self.calibrator.probs,
                           "tail_scale": self.calibrator.tail_scale},
            "stage_b": self.stage_b,
            "baseline_median": self.baseline_median,
            "meta": self.meta.as_dict(),
        }, path, compress=3)
        return path

    @classmethod
    def load(cls, path: Path | None = None) -> "DetectionModel":
        path = path or settings.stage_a_path
        blob = joblib.load(path)
        if blob.get("format") != MODEL_FORMAT:
            raise ValueError(
                f"model {path.name} has format {blob.get('format')}, this build expects "
                f"{MODEL_FORMAT}; retrain with `aegis train`"
            )
        stored = tuple(blob.get("features", ()))
        if stored != FEATURE_NAMES:
            raise ValueError(
                f"model {path.name} was trained on {len(stored)} features, this build "
                f"computes {len(FEATURE_NAMES)}; retrain with `aegis train`"
            )
        model = cls()
        model.stage_a = blob["stage_a"]
        cal = blob["calibrator"]
        model.calibrator.grid = cal["grid"]
        model.calibrator.probs = cal["probs"]
        model.calibrator.tail_scale = cal["tail_scale"]
        model.stage_b = blob.get("stage_b")
        model.baseline_median = blob.get("baseline_median")
        meta = blob.get("meta", {})
        model.meta = ModelMeta(
            trained_at=meta.get("trained_at", ""),
            train_flows_benign=meta.get("train_flows_benign", 0),
            train_flows_labelled=meta.get("train_flows_labelled", 0),
            train_seeds=meta.get("train_seeds"),
            test_seeds=meta.get("test_seeds"),
            classes=meta.get("classes"),
            metrics=meta.get("metrics"),
            notes=meta.get("notes", ""),
        )
        return model
