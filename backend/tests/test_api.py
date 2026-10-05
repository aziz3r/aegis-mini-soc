"""API surface: auth, roles, triage, and the persistence path.

The persistence test exists because of a real bug: SQLAlchemy applies column
defaults at INSERT, so a freshly constructed row still held `None` in memory and
the first `+=` on a counter killed the ingest task. A unit test on the writer
would not have caught it; only exercising the real write path does.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(db):
    from aegis.api.app import app
    from aegis.api.auth import hash_password
    from aegis.store.db import User, session_scope

    with session_scope() as sess:
        for username, role in (("admin", "admin"), ("ana", "analyst"), ("lec", "viewer")):
            if not sess.get(User, username):
                sess.add(User(username=username, password_hash=hash_password("pw"), role=role))
    with TestClient(app) as c:
        yield c


def token(client, username: str) -> dict[str, str]:
    response = client.post("/api/auth/token", data={"username": username, "password": "pw"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


class TestAuth:
    def test_rejects_wrong_password(self, client):
        assert client.post("/api/auth/token",
                           data={"username": "admin", "password": "nope"}).status_code == 401

    def test_rejects_unknown_user(self, client):
        assert client.post("/api/auth/token",
                           data={"username": "ghost", "password": "pw"}).status_code == 401

    def test_protected_route_needs_a_token(self, client):
        assert client.get("/api/incidents").status_code == 401

    def test_rejects_a_forged_token(self, client):
        bad = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.forged"}
        assert client.get("/api/incidents", headers=bad).status_code == 401

    def test_token_carries_the_role(self, client):
        me = client.get("/api/auth/me", headers=token(client, "ana")).json()
        assert me == {"username": "ana", "role": "analyst"}


class TestRoles:
    def test_viewer_cannot_triage(self, client):
        r = client.patch("/api/incidents/1", json={"status": "ACK"}, headers=token(client, "lec"))
        assert r.status_code == 403
        assert "analyst" in r.json()["detail"]

    def test_analyst_cannot_change_settings(self, client):
        r = client.put("/api/settings/assets", json={"entries": []}, headers=token(client, "ana"))
        assert r.status_code == 403

    def test_analyst_cannot_start_a_source(self, client):
        r = client.post("/api/pipeline/start", json={"source": "lab"}, headers=token(client, "ana"))
        assert r.status_code == 403

    def test_viewer_can_read(self, client):
        assert client.get("/api/incidents", headers=token(client, "lec")).status_code == 200


@pytest.fixture(scope="module")
def incident_id(client):
    """Drive the real writer once, then let the triage tests work that incident."""
    from aegis.core.assets import AssetRegistry
    from aegis.core.correlate import Correlator
    from aegis.core.types import Flow, FlowKey, Verdict
    from aegis.store.writer import BucketDelta, HostDelta, Writer

    corr = Correlator()
    writer = Writer()
    events = []
    for port in range(12):
        key = FlowKey("203.0.113.9", "192.168.1.10", 40000 + port, port, "tcp")
        flow = Flow(key, 0.0, 1.0, {"syn_count": 1.0}, label="PORT_SCAN")
        flow.fwd_packets, flow.fwd_bytes = 1, 74
        events.append(corr.ingest(Verdict(flow=flow, score=0.995, threshold=0.98,
                                          is_alert=True, family="PORT_SCAN",
                                          family_confidence=0.99)))
    payloads = writer.flush_incidents(events)
    assert len(payloads) == 1, "a scan must persist as exactly one incident"
    assert payloads[0]["occurrences"] == 12

    # the path that used to crash on a None counter
    writer.flush_hosts({"203.0.113.9": HostDelta(flows_out=12, bytes_out=888, alerts=12,
                                                 score_sum=11.9, score_n=12, threshold=0.98)},
                       AssetRegistry())
    writer.flush_hosts({"203.0.113.9": HostDelta(flows_out=3, bytes_out=200, alerts=3,
                                                 score_sum=2.9, score_n=3, threshold=0.98)},
                       AssetRegistry())
    writer.flush_bucket(BucketDelta(ts=datetime.now(timezone.utc), flows=15, alerts=12,
                                    packets=15, bytes=1088, score_sum=14.0, score_max=0.995,
                                    threshold_sum=14.7))
    return payloads[0]["id"]


class TestPersistenceAndTriage:

    def test_host_counters_accumulate_across_flushes(self, client, incident_id):
        rows = client.get("/api/hosts", headers=token(client, "lec")).json()["items"]
        host = next(h for h in rows if h["ip"] == "203.0.113.9")
        assert host["flows_out"] == 15 and host["alerts"] == 15
        assert host["bytes_out"] == 1088

    def test_incident_detail_carries_its_alerts(self, client, incident_id):
        detail = client.get(f"/api/incidents/{incident_id}", headers=token(client, "lec")).json()
        assert detail["occurrences"] == 12
        assert len(detail["alerts"]) == 12
        assert detail["distinct_dports"] == 12
        assert detail["guidance"]["technique"] == "T1046"
        assert detail["ground_truth"] == {"PORT_SCAN": 12}

    def test_analyst_can_acknowledge(self, client, incident_id):
        r = client.patch(f"/api/incidents/{incident_id}", json={"status": "ACK"},
                         headers=token(client, "ana"))
        assert r.status_code == 200 and r.json()["status"] == "ACK"

    def test_a_verdict_closes_the_incident(self, client, incident_id):
        r = client.patch(f"/api/incidents/{incident_id}", json={"verdict": "TP"},
                         headers=token(client, "ana"))
        assert r.status_code == 200
        assert r.json()["verdict"] == "TP"
        assert r.json()["status"] == "CLOSED", "a judged incident is a closed incident"

    def test_notes_are_appended_and_attributed(self, client, incident_id):
        client.patch(f"/api/incidents/{incident_id}", json={"note": "première note"},
                     headers=token(client, "ana"))
        client.patch(f"/api/incidents/{incident_id}", json={"note": "seconde note"},
                     headers=token(client, "ana"))
        note = client.get(f"/api/incidents/{incident_id}", headers=token(client, "ana")).json()["note"]
        assert "première note" in note and "seconde note" in note and "ana" in note

    def test_every_change_is_audited(self, client, incident_id):
        entries = client.get("/api/audit", headers=token(client, "admin")).json()["items"]
        actions = {e["action"] for e in entries}
        assert "incident.update" in actions
        assert any(e["actor"] == "ana" for e in entries)

    def test_overview_reflects_the_incident(self, client, incident_id):
        data = client.get("/api/overview?hours=24", headers=token(client, "lec")).json()
        assert data["incidents_total"] >= 1
        assert data["feedback"]["true_positive"] >= 1
        assert data["by_family"].get("PORT_SCAN", 0) >= 1


class TestValidation:
    def test_detection_settings_are_range_checked(self, client):
        r = client.put("/api/settings/detection", headers=token(client, "admin"),
                       json={"base_threshold": 0.5, "min_threshold": 0.9, "max_threshold": 0.99,
                             "host_quantile": 0.99, "dedup_window": 60,
                             "supervised_min_confidence": 0.5})
        assert r.status_code == 400, "min must not exceed base"

    def test_unknown_pcap_is_rejected(self, client):
        r = client.post("/api/pipeline/start", headers=token(client, "admin"),
                        json={"source": "pcap", "file": "does-not-exist.pcap"})
        assert r.status_code == 404

    def test_pcap_path_cannot_escape_its_directory(self, client):
        r = client.post("/api/pipeline/start", headers=token(client, "admin"),
                        json={"source": "pcap", "file": "../../etc/passwd"})
        assert r.status_code == 404

    def test_unknown_incident_is_404(self, client):
        assert client.get("/api/incidents/999999", headers=token(client, "lec")).status_code == 404


class TestHealth:
    def test_health_is_public(self, client):
        body = client.get("/api/health").json()
        assert body["status"] in {"ok", "degraded"}
        assert "version" in body
