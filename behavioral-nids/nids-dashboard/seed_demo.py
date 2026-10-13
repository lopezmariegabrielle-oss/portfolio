"""Remplit la base avec des DONNEES DE DEMONSTRATION (fausses, signalees dans le dashboard).

    python seed_demo.py           # genere 24 h d'historique, puis quitte
    python seed_demo.py --live    # idem, puis ajoute du trafic chaque seconde (Ctrl+C pour arreter)

Les IPs utilisent des plages reservees a la documentation (RFC 5737) et au reseau prive.
Attention : le script REINITIALISE les tables alerts et traffic.
"""
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import db

ISO = "%Y-%m-%dT%H:%M:%SZ"
EXTERNAL = ["203.0.113.%d" % i for i in (7, 23, 58, 101, 166)] + ["198.51.100.%d" % i for i in (14, 77, 203)]
INTERNAL = ["192.168.1.%d" % i for i in (10, 24, 31, 42, 57, 88)]
SCENARIOS = [
    ("TCP", 22, "Rafale de tentatives SSH inhabituelle", (0.72, 0.97)),
    ("TCP", 445, "Balayage de ports SMB depuis un hote interne", (0.78, 0.95)),
    ("UDP", 53, "Volume DNS anormal (exfiltration possible)", (0.62, 0.88)),
    ("TCP", 443, "Connexion sortante vers une destination rare", (0.55, 0.8)),
    ("TCP", 3389, "Acces RDP hors des horaires habituels", (0.66, 0.9)),
    ("ICMP", None, "Pic de requetes ICMP", (0.4, 0.65)),
]


def fmt(dt):
    return dt.strftime(ISO)


def make_alert(conn, when):
    proto, port, reason, (lo, hi) = random.choice(SCENARIOS)
    src = random.choice(EXTERNAL if random.random() < 0.7 else INTERNAL)
    # on favorise quelques sources pour que "source la plus active" soit parlant
    if random.random() < 0.3:
        src = EXTERNAL[0]
    dst = random.choice(INTERNAL)
    db.insert_alert(conn, fmt(when), src, dst, round(random.uniform(lo, hi), 2),
                    dst_port=port, proto=proto, reason=reason)


def seed(path=None):
    random.seed(42)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    with db.connect(path) as conn:
        conn.executescript(db.SCHEMA)
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM traffic")
        db.set_meta(conn, "demo", "1")
        for i in range(24 * 60):
            minute = now - timedelta(minutes=i)
            hour = minute.hour
            base = 90 + 60 * (1 if 8 <= hour <= 19 else 0)  # plus de trafic en journee
            flows = max(0, int(random.gauss(base, 15)))
            anomalies = 0
            if random.random() < 0.06:
                anomalies = random.randint(1, 6)
                for _ in range(random.randint(1, min(anomalies, 2))):
                    make_alert(conn, minute + timedelta(seconds=random.randint(0, 59)))
            db.add_traffic(conn, fmt(minute), flows, anomalies)


def live(path=None):
    print("Mode live : Ctrl+C pour arreter.")
    while True:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        flows = random.randint(1, 4)
        anomalies = 1 if random.random() < 0.04 else 0
        with db.connect(path) as conn:
            db.add_traffic(conn, fmt(now.replace(second=0)), flows, anomalies)
            if anomalies:
                make_alert(conn, now)
        time.sleep(1)


if __name__ == "__main__":
    db.init_db()
    seed()
    print("Donnees de demonstration generees dans", db.DB_PATH)
    if "--live" in sys.argv:
        try:
            live()
        except KeyboardInterrupt:
            print("\nArret.")
