import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402
from app import create_app  # noqa: E402

ISO = "%Y-%m-%dT%H:%M:%SZ"


def ts(minutes_ago=0):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    return (now - timedelta(minutes=minutes_ago)).strftime(ISO)


@pytest.fixture
def client(tmp_path):
    path = str(tmp_path / "t.db")
    app = create_app(path)
    with db.connect(path) as c:
        db.add_traffic(c, ts(0), 100, 2)
        db.add_traffic(c, ts(1), 50, 0)
        db.insert_alert(c, ts(1), "203.0.113.7", "192.168.1.10", 0.95, 22, "TCP", "ssh")
        db.insert_alert(c, ts(2), "203.0.113.7", "192.168.1.11", 0.7, 445, "TCP", "smb")
        db.insert_alert(c, ts(3), "198.51.100.14", "192.168.1.12", 0.3, None, "ICMP", "icmp")
        db.set_meta(c, "demo", "1")
    return app.test_client()


def test_stats(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    d = r.get_json()
    assert d["flows_24h"] == 150
    assert d["alerts_24h"] == 3
    assert d["by_severity"] == {"low": 1, "medium": 1, "high": 0, "critical": 1}
    assert d["top_source"] == {"ip": "203.0.113.7", "count": 2}
    assert d["anomaly_rate"] == round(100 * 2 / 150, 2)
    assert d["demo"] is True


def test_stats_empty(tmp_path):
    c = create_app(str(tmp_path / "e.db")).test_client()
    d = c.get("/api/stats").get_json()
    assert d["flows_24h"] == 0 and d["top_source"] is None and d["anomaly_rate"] == 0
    assert d["demo"] is False


def test_traffic_shape_and_clamp(client):
    d = client.get("/api/traffic?minutes=60").get_json()
    assert len(d["points"]) == 60
    assert sum(p["flows"] for p in d["points"]) == 150
    assert client.get("/api/traffic?minutes=1").get_json()["minutes"] == 5
    assert client.get("/api/traffic?minutes=999999").get_json()["minutes"] == 1440


def test_traffic_invalid(client):
    assert client.get("/api/traffic?minutes=abc").status_code == 400


def test_alerts_order_and_paging(client):
    d = client.get("/api/alerts").get_json()
    assert d["total"] == 3
    assert [a["reason"] for a in d["items"]] == ["ssh", "smb", "icmp"]
    d = client.get("/api/alerts?limit=1&offset=1").get_json()
    assert len(d["items"]) == 1 and d["items"][0]["reason"] == "smb"
    assert len(client.get("/api/alerts?limit=99999").get_json()["items"]) == 3


def test_alerts_filter(client):
    d = client.get("/api/alerts?severity=critical").get_json()
    assert d["total"] == 1 and d["items"][0]["severity"] == "critical"


@pytest.mark.parametrize("q", [
    "severity=urgent",
    "severity=low'%20OR%20'1'='1",
    "severity=critical;DROP%20TABLE%20alerts",
    "limit=abc",
    "offset=1;DROP",
])
def test_alerts_bad_params(client, q):
    r = client.get("/api/alerts?" + q)
    assert r.status_code == 400
    assert "error" in r.get_json()
    assert client.get("/api/alerts").get_json()["total"] == 3  # la table est intacte


def test_security_headers(client):
    r = client.get("/api/stats")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


def test_index_page(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Behavioral NIDS" in r.data
    assert client.get("/static/app.js").status_code == 200


# ---------------------------------------------------------------- statut des alertes
def _first_id(client):
    return client.get("/api/alerts").get_json()["items"][0]["id"]


def test_alert_default_status_and_to_review(client):
    d = client.get("/api/alerts").get_json()
    assert all(a["status"] == "new" for a in d["items"])
    assert client.get("/api/stats").get_json()["to_review"] == 3


def test_update_status(client):
    i = _first_id(client)
    r = client.patch(f"/api/alerts/{i}", json={"status": "false_positive"})
    assert r.status_code == 200 and r.get_json() == {"id": i, "status": "false_positive"}
    assert client.get("/api/alerts?status=false_positive").get_json()["total"] == 1
    assert client.get("/api/alerts?status=new").get_json()["total"] == 2
    assert client.get("/api/stats").get_json()["to_review"] == 2


@pytest.mark.parametrize("body", [{"status": "hacked"}, {"status": None}, {}, {"status": "new'; DROP TABLE alerts;--"}])
def test_update_status_invalid(client, body):
    i = _first_id(client)
    assert client.patch(f"/api/alerts/{i}", json=body).status_code == 400
    assert client.get("/api/alerts").get_json()["total"] == 3


def test_update_status_unknown_id_and_wrong_type(client):
    assert client.patch("/api/alerts/99999", json={"status": "resolved"}).status_code == 404
    i = _first_id(client)
    assert client.patch(f"/api/alerts/{i}", data="status=resolved").status_code == 415


def test_update_status_cross_origin_refused(client):
    i = _first_id(client)
    r = client.patch(f"/api/alerts/{i}", json={"status": "resolved"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.get("/api/alerts?status=resolved").get_json()["total"] == 0


def test_filter_invalid_status(client):
    assert client.get("/api/alerts?status=x").status_code == 400


def test_old_database_is_migrated(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, src_ip TEXT NOT NULL,"
                    " dst_ip TEXT NOT NULL, dst_port INTEGER, proto TEXT, score REAL NOT NULL, severity TEXT NOT NULL,"
                    " reason TEXT); INSERT INTO alerts (ts, src_ip, dst_ip, score, severity)"
                    " VALUES ('2026-10-13T10:00:00Z','1.1.1.1','2.2.2.2',0.9,'high');")
    c.commit(); c.close()
    cl = create_app(path).test_client()
    assert cl.get("/api/alerts").get_json()["items"][0]["status"] == "new"
