import sqlite3
from datetime import datetime, timezone

import db
from engine import run_detection


def cols_of(path):
    with db.connect(path) as c:
        return [r["name"] for r in c.execute("PRAGMA table_info(alerts)")]


def test_nouvelle_base_a_les_colonnes(tmp_path):
    p = str(tmp_path / "a.db")
    db.init_db(p)
    assert {"reputation_score", "country"} <= set(cols_of(p))


def test_ancienne_base_migree_sans_perte(tmp_path):
    p = str(tmp_path / "old.db")
    conn = sqlite3.connect(p)
    conn.executescript(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER, proto TEXT, "
        "score REAL NOT NULL, severity TEXT NOT NULL, reason TEXT, "
        "status TEXT NOT NULL DEFAULT 'new');"
        "INSERT INTO alerts (ts, src_ip, dst_ip, score, severity) "
        "VALUES ('2026-10-15T09:00:00Z','1.1.1.1','2.2.2.2',0.8,'high');")
    conn.commit()
    conn.close()
    db.init_db(p)
    db.init_db(p)  # relancer ne casse rien
    with db.connect(p) as c:
        row = c.execute("SELECT * FROM alerts").fetchone()
    assert row["src_ip"] == "1.1.1.1"
    assert row["reputation_score"] is None and row["country"] is None


def test_insert_alert_avec_et_sans_reputation(tmp_path):
    p = str(tmp_path / "b.db")
    db.init_db(p)
    with db.connect(p) as c:
        db.insert_alert(c, "2026-10-15T09:00:00Z", "8.8.8.8", "10.0.0.2", 0.9,
                        reputation_score=87, country="FR")
        db.insert_alert(c, "2026-10-15T09:00:01Z", "10.0.0.3", "10.0.0.2", 0.7)
    with db.connect(p) as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    assert (rows[0]["reputation_score"], rows[0]["country"]) == (87, "FR")
    assert rows[1]["reputation_score"] is None


class FakeDet:
    def score(self, flows):
        return [1.0] * len(flows)

    def explain(self, f):
        return "test"


class FakeClient:
    enabled = True

    def enrich(self, src, dst):
        return {"reputation_score": 90, "country": "RU"}


FLOWS = [{"src_ip": "203.0.113.9", "dst_ip": "192.168.1.5", "dst_port": 22, "proto": "TCP"}]
NOW = datetime(2026, 10, 15, 9, 0, 0, tzinfo=timezone.utc)


def test_process_enrichit_les_alertes(tmp_path, monkeypatch):
    p = str(tmp_path / "c.db")
    db.init_db(p)
    monkeypatch.setattr(run_detection, "_reputation", lambda: FakeClient())
    with db.connect(p) as c:
        assert run_detection.process(c, FakeDet(), FLOWS, NOW) == 1
    with db.connect(p) as c:
        row = c.execute("SELECT * FROM alerts").fetchone()
    assert (row["reputation_score"], row["country"]) == (90, "RU")


def test_process_sans_enrich_n_appelle_pas_abuseipdb(tmp_path, monkeypatch):
    p = str(tmp_path / "d.db")
    db.init_db(p)

    def boom():
        raise AssertionError("AbuseIPDB ne doit pas etre appele")

    monkeypatch.setattr(run_detection, "_reputation", boom)
    with db.connect(p) as c:
        run_detection.process(c, FakeDet(), FLOWS, NOW, enrich=False)
    with db.connect(p) as c:
        assert c.execute("SELECT reputation_score FROM alerts").fetchone()[0] is None