"""Acces SQLite du NIDS : schema + fonctions d'ecriture.

Ton moteur d'analyse Python appelle `insert_alert` et `add_traffic` ;
l'API Flask (app.py) ne fait que LIRE ces tables.
"""
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "NIDS_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "nids.db"),
)

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("new", "investigating", "false_positive", "resolved")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,              -- ISO 8601 UTC : 2026-10-13T09:44:00Z
    src_ip    TEXT    NOT NULL,
    dst_ip    TEXT    NOT NULL,
    dst_port  INTEGER,
    proto     TEXT,
    score     REAL    NOT NULL CHECK (score >= 0 AND score <= 1),
    severity  TEXT    NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    reason    TEXT,
    status    TEXT    NOT NULL DEFAULT 'new' CHECK (status IN ('new','investigating','false_positive','resolved'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS traffic (
    minute    TEXT PRIMARY KEY,              -- debut de minute : 2026-10-13T09:44:00Z
    flows     INTEGER NOT NULL DEFAULT 0,
    anomalies INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


@contextmanager
def connect(path=None):
    """Ouvre une connexion, commit a la sortie, ferme toujours."""
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path=None):
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        # Migration : une base creee avant l'ajout du statut n'a pas cette colonne
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(alerts)")]
        if "status" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")


def severity_from_score(score):
    """Traduit le score d'anomalie (0..1) du modele en niveau de severite."""
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def insert_alert(conn, ts, src_ip, dst_ip, score, dst_port=None, proto=None,
                 reason=None, severity=None):
    """Enregistre une alerte. `ts` doit etre au format 'YYYY-MM-DDTHH:MM:SSZ' (UTC)."""
    if not 0 <= score <= 1:
        raise ValueError("score doit etre compris entre 0 et 1")
    severity = severity or severity_from_score(score)
    conn.execute(
        "INSERT INTO alerts (ts, src_ip, dst_ip, dst_port, proto, score, severity, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, src_ip, dst_ip, dst_port, proto, score, severity, reason),
    )


def add_traffic(conn, minute, flows, anomalies=0):
    """Ajoute des flux a la minute donnee (cumulatif : peut etre appele plusieurs fois)."""
    conn.execute(
        "INSERT INTO traffic (minute, flows, anomalies) VALUES (?, ?, ?) "
        "ON CONFLICT(minute) DO UPDATE SET "
        "flows = flows + excluded.flows, anomalies = anomalies + excluded.anomalies",
        (minute, flows, anomalies),
    )


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default
