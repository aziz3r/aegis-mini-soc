"""Model persistence and the guards that protect a served model."""
from __future__ import annotations

import numpy as np
import pytest

from aegis.core.features import FEATURE_NAMES
from aegis.ml.model import MODEL_FORMAT, DetectionModel


class TestPersistence:
    def test_round_trips_through_disk(self, tiny_model, tmp_path):
        path = tiny_model.save(tmp_path / "m.joblib")
        loaded = DetectionModel.load(path)
        assert loaded.is_ready
        rng = np.random.default_rng(0)
        X = rng.random((40, len(FEATURE_NAMES))).astype(np.float32) * 100
        assert np.allclose(tiny_model.score(X), loaded.score(X))

    def test_refuses_a_different_feature_set(self, tiny_model, tmp_path):
        """A silently shifted column is the worst failure mode here."""
        import joblib

        path = tiny_model.save(tmp_path / "m.joblib")
        blob = joblib.load(path)
        blob["features"] = list(FEATURE_NAMES)[:-1]
        joblib.dump(blob, path)
        with pytest.raises(ValueError, match="features"):
            DetectionModel.load(path)

    def test_refuses_an_older_format(self, tiny_model, tmp_path):
        import joblib

        path = tiny_model.save(tmp_path / "m.joblib")
        blob = joblib.load(path)
        blob["format"] = MODEL_FORMAT - 1
        joblib.dump(blob, path)
        with pytest.raises(ValueError, match="format"):
            DetectionModel.load(path)


class TestScoring:
    def test_scores_are_bounded(self, tiny_model):
        rng = np.random.default_rng(1)
        X = rng.random((200, len(FEATURE_NAMES))).astype(np.float32) * 1e6
        scores = tiny_model.score(X)
        assert np.all((scores >= 0.0) & (scores < 1.0))
        assert np.all(np.isfinite(scores))

    def test_extreme_input_does_not_explode(self, tiny_model):
        X = np.full((3, len(FEATURE_NAMES)), 1e9, dtype=np.float32)
        assert np.all(np.isfinite(tiny_model.score(X)))

    def test_classification_declines_when_unsure(self, tiny_model):
        from aegis.config import settings

        rng = np.random.default_rng(2)
        X = rng.random((50, len(FEATURE_NAMES))).astype(np.float32)
        families, confidence = tiny_model.classify(X)
        for family, conf in zip(families, confidence):
            if conf < settings.supervised_min_confidence:
                assert family == "UNKNOWN"

    def test_explanation_shares_sum_to_at_most_one(self, tiny_model):
        from aegis.ml.dataset import vectorize_many
        from aegis.core.flows import FlowTable
        from aegis.sources.lab import LabNetwork

        net = LabNetwork(seed=6)
        flows = list(FlowTable().feed(net.generate(90.0, net.plan(90.0))))
        X = vectorize_many(flows)
        worst = int(np.argmax(tiny_model.score(X)))
        contributions = tiny_model.explain(X[worst])
        assert contributions
        assert sum(c.impact for c in contributions) <= 1.0 + 1e-6
        assert all(c.feature for c in contributions)
