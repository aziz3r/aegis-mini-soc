"""Test fixtures.

Each test module gets its own throwaway SQLite file, so the suite never touches
`data/aegis.db` and tests cannot see each other's rows.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

TMP = Path(tempfile.mkdtemp(prefix="aegis-tests-"))
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{TMP / 'test.db'}"


@pytest.fixture(scope="session")
def db():
    from aegis.store.db import init_db
    init_db(drop=True)
    yield


@pytest.fixture(scope="session")
def trained_model():
    """The model on disk, or skip - unit tests must not silently train one."""
    from aegis.ml.model import DetectionModel
    try:
        return DetectionModel.load()
    except (FileNotFoundError, ValueError) as exc:
        pytest.skip(f"aucun modèle entraîné disponible ({exc}); lancez `aegis train`")


@pytest.fixture
def tiny_model():
    """A deliberately small model, fast enough to fit in a unit test."""
    import numpy as np
    from aegis.ml.dataset import simulate_capture, stack
    from aegis.ml.model import DetectionModel

    benign = simulate_capture(4242, 90.0, benign_only=True)
    X, _ = stack([benign])
    model = DetectionModel()
    model.fit_stage_a(X, n_estimators=40)
    mixed = simulate_capture(77, 90.0)
    Xm, ym = stack([mixed])
    if len(set(ym)) > 1:
        model.fit_stage_b(Xm, ym)
    assert np.isfinite(X).all()
    return model
