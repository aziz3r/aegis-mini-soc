"""Calibration, adaptive threshold, cascade, correlation."""
from __future__ import annotations

import numpy as np
import pytest

from aegis.config import settings
from aegis.core.correlate import Correlator, dedup_key
from aegis.core.engine import Engine
from aegis.core.types import Flow, FlowKey, Verdict
from aegis.ml.model import EcdfCalibrator
from aegis.ml.threshold import AdaptiveThreshold


class TestCalibrator:
    def test_recovers_the_normal_cdf(self):
        """A calibrated score must be readable as 'more unusual than X% of normal'."""
        rng = np.random.default_rng(0)
        cal = EcdfCalibrator().fit(rng.normal(0, 1, 60_000))
        assert cal.transform(np.array([0.0]))[0] == pytest.approx(0.5, abs=0.01)
        assert cal.transform(np.array([1.0]))[0] == pytest.approx(0.8413, abs=0.01)
        assert cal.transform(np.array([1.96]))[0] == pytest.approx(0.975, abs=0.01)

    def test_is_monotonic(self):
        rng = np.random.default_rng(1)
        cal = EcdfCalibrator().fit(rng.normal(0, 1, 20_000))
        out = cal.transform(np.sort(rng.normal(0, 1, 2_000)))
        assert np.all(np.diff(out) >= -1e-12)

    def test_tail_keeps_ranking_instead_of_saturating(self):
        rng = np.random.default_rng(2)
        cal = EcdfCalibrator().fit(rng.normal(0, 1, 20_000))
        far, further = cal.transform(np.array([8.0]))[0], cal.transform(np.array([40.0]))[0]
        assert far < further < 1.0, "beyond the benign maximum, order must be preserved"

    def test_never_reaches_exactly_one(self):
        cal = EcdfCalibrator().fit(np.random.default_rng(3).normal(0, 1, 5_000))
        assert cal.transform(np.array([1e6]))[0] < 1.0


class TestAdaptiveThreshold:
    def test_quiet_host_keeps_the_global_floor(self):
        at = AdaptiveThreshold()
        rng = np.random.default_rng(4)
        for s in rng.uniform(0.0, 0.6, 300):
            at.observe("quiet", float(s), alerted=False)
        assert at.threshold("quiet") == pytest.approx(settings.base_threshold)

    def test_legitimately_odd_host_raises_its_own_bar(self):
        at = AdaptiveThreshold()
        rng = np.random.default_rng(5)
        for s in np.clip(rng.beta(7, 1.1, 400), 0, 0.9999):
            at.observe("backup", float(s), alerted=False)
        assert at.threshold("backup") > settings.base_threshold
        assert at.threshold("backup") <= settings.max_threshold

    def test_cold_start_is_the_floor(self):
        assert AdaptiveThreshold().threshold("unknown") == pytest.approx(settings.base_threshold)

    def test_alerting_scores_never_enter_the_baseline(self):
        """The boiling-frog guard: a sustained attack must not raise its own bar."""
        at = AdaptiveThreshold()
        for s in np.random.default_rng(6).uniform(0, 0.5, 200):
            at.observe("victim", float(s), alerted=False)
        before = at.threshold("victim")
        for _ in range(5_000):
            at.observe("victim", 0.999, alerted=True)
        assert at.threshold("victim") == pytest.approx(before)

    def test_threshold_is_bounded(self):
        at = AdaptiveThreshold()
        for _ in range(300):
            at.observe("h", 0.99999, alerted=False)
        assert settings.min_threshold <= at.threshold("h") <= settings.max_threshold


def _verdict(src, dst, dport, family, score=0.99, threshold=0.98):
    key = FlowKey(src, dst, 40000, dport, "tcp")
    flow = Flow(key, 0.0, 1.0, {}, label="BENIGN")
    flow.fwd_packets, flow.fwd_bytes = 2, 120
    return Verdict(flow=flow, score=score, threshold=threshold, is_alert=True,
                   family=family, family_confidence=0.95)


class TestCorrelation:
    def test_scan_collapses_to_one_incident(self):
        corr = Correlator()
        for port in range(400):
            corr.ingest(_verdict("1.2.3.4", "10.0.0.1", port, "PORT_SCAN"))
        assert corr.incidents_opened == 1
        assert corr.active[0].occurrences == 400
        assert len(corr.active[0].dports) == 400

    def test_flood_groups_on_the_victim(self):
        """Many spoofed sources, one victim: grouping on the pair would make 200 rows."""
        corr = Correlator()
        for i in range(200):
            corr.ingest(_verdict(f"88.0.0.{i % 200}", "10.0.0.1", 80, "DOS_FLOOD"))
        assert corr.incidents_opened == 1
        assert len(corr.active[0].peers) > 100

    def test_distinct_bruteforce_sources_stay_separate(self):
        corr = Correlator()
        corr.ingest(_verdict("1.1.1.1", "10.0.0.1", 22, "SSH_BRUTEFORCE"))
        corr.ingest(_verdict("2.2.2.2", "10.0.0.1", 22, "SSH_BRUTEFORCE"))
        assert corr.incidents_opened == 2

    def test_dedup_key_shape_per_family(self):
        assert dedup_key(_verdict("a", "b", 1, "PORT_SCAN")).endswith("|*")
        assert "|*|" in dedup_key(_verdict("a", "b", 1, "DOS_FLOOD"))
        assert dedup_key(_verdict("a", "b", 1, "C2_BEACON")) == "C2_BEACON|a|b"

    def test_asset_criticality_raises_priority(self):
        corr = Correlator()
        on_server = corr.ingest(_verdict("1.2.3.4", "192.168.1.10", 80, "PORT_SCAN")).incident
        corr2 = Correlator()
        on_desktop = corr2.ingest(_verdict("1.2.3.4", "192.168.1.55", 80, "PORT_SCAN")).incident
        assert on_server.criticality >= on_desktop.criticality
        assert on_server.priority >= on_desktop.priority

    def test_window_expiry_retires_incidents(self):
        from datetime import datetime, timedelta, timezone
        corr = Correlator()
        now = datetime.now(timezone.utc)
        corr.ingest(_verdict("1.2.3.4", "10.0.0.1", 80, "PORT_SCAN"), now)
        assert corr.sweep(now + timedelta(seconds=settings.dedup_window / 2)) == []
        assert len(corr.sweep(now + timedelta(seconds=settings.dedup_window + 1))) == 1


class TestCascade:
    def test_suppression_requires_confidence_and_a_marginal_score(self, tiny_model):
        """Stage B may veto a marginal alert, never a strong anomaly."""
        engine = Engine(tiny_model, explain=False)
        assert settings.alert_override_score > settings.base_threshold
        assert settings.benign_suppress_confidence > settings.supervised_min_confidence

    def test_strong_anomalies_are_never_suppressed(self, tiny_model):
        """What preserves detection of attacks the classifier has never seen."""
        from aegis.ml.dataset import vectorize_many
        from aegis.sources.lab import LabNetwork
        from aegis.core.flows import FlowTable

        net = LabNetwork(seed=9)
        flows = list(FlowTable().feed(net.generate(60.0, net.plan(60.0))))
        engine = Engine(tiny_model, explain=False)
        verdicts = engine.score_flows(flows)
        for v in verdicts:
            if v.score >= settings.alert_override_score:
                assert v.is_alert, "a score above the override must always alert"


class TestEngine:
    def test_threshold_is_read_before_the_score_is_learned(self, tiny_model):
        """A flow must never influence the threshold it is judged against."""
        from aegis.core.flows import FlowTable
        from aegis.sources.lab import LabNetwork

        net = LabNetwork(seed=3)
        flows = list(FlowTable().feed(net.generate(40.0, [])))
        engine = Engine(tiny_model, explain=False)
        verdicts = engine.score_flows(flows[:5])
        for v in verdicts:
            assert v.threshold == pytest.approx(settings.base_threshold), (
                "the first flows of a host must see the cold-start floor"
            )

    def test_explanation_is_produced_for_alerts(self, tiny_model):
        import numpy as np
        from aegis.ml.dataset import vectorize_many
        from aegis.core.flows import FlowTable
        from aegis.sources.lab import LabNetwork

        net = LabNetwork(seed=12)
        flows = list(FlowTable().feed(net.generate(120.0, net.plan(120.0))))
        X = vectorize_many(flows)
        worst = int(np.argmax(tiny_model.score(X)))
        contributions = tiny_model.explain(X[worst])
        assert contributions, "the worst-scoring flow must have an explanation"
        assert all(0.0 <= c.impact <= 1.0 for c in contributions)
        assert sum(c.impact for c in contributions) <= 1.0 + 1e-6
        assert all(c.direction in ("above", "below") for c in contributions)
