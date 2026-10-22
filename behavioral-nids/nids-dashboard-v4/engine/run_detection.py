"""Moteur de detection : simule un flux de trafic, le fait noter par le modele, ecrit dans la base.

    python engine/run_detection.py              # tourne jusqu'a Ctrl+C
    python engine/run_detection.py --seconds 60 # s'arrete apres 60 s

ATTENTION : le trafic est SIMULE (engine/simulate.py). Le modele est reel ; seules les donnees
d'entree sont fictives. La capture reseau reelle viendra remplacer `next_flows()`.
"""
import argparse
import os
import pickle
import sys
import time
from datetime import datetime, timezone

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import db  # noqa: E402
from engine import simulate  # noqa: E402
from engine.model import ALERT_THRESHOLD  # noqa: E402

try:  # reputation AbuseIPDB (optionnelle)
    from reputation import ReputationClient  # noqa: E402
except ImportError:
    ReputationClient = None

_rep_client = None


def _reputation():
    """Client AbuseIPDB cree a la demande ; None s'il est desactive (pas de cle)."""
    global _rep_client
    if _rep_client is None and ReputationClient is not None:
        _rep_client = ReputationClient()
    return _rep_client if _rep_client is not None and _rep_client.enabled else None

MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
ISO = "%Y-%m-%dT%H:%M:%SZ"


def load_model(path=MODEL):
    # pickle : ne charger que SON PROPRE modele (un pickle peut executer du code a la lecture)
    with open(path, "rb") as fh:
        return pickle.load(fh)


def next_flows(rng, attack_prob=0.03):
    """Source de flux. A remplacer plus tard par la capture reseau reelle."""
    n = int(rng.integers(1, 5))
    flows = simulate.normal_flows(n, rng)
    if rng.random() < attack_prob:
        flows += simulate.attack_flows(int(rng.integers(1, 3)), rng)
    return flows


def process(conn, det, flows, now, enrich=True):
    """Note les flux, met a jour le trafic de la minute, cree les alertes. Renvoie le nb d'alertes."""
    scores = det.score(flows)
    alerts = 0
    for f, sc in zip(flows, scores):
        if sc >= ALERT_THRESHOLD:
            alerts += 1
            client = _reputation() if enrich else None
            rep = client.enrich(f["src_ip"], f["dst_ip"]) if client else None
            db.insert_alert(conn, now.strftime(ISO), f["src_ip"], f["dst_ip"], float(sc),
                            dst_port=f["dst_port"], proto=f["proto"], reason=det.explain(f),
                            reputation_score=rep["reputation_score"] if rep else None,
                            country=rep["country"] if rep else None)
    db.add_traffic(conn, now.replace(second=0).strftime(ISO), len(flows), alerts)
    return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=0, help="duree (0 = jusqu'a Ctrl+C)")
    ap.add_argument("--reset", action="store_true", help="vider alertes et trafic avant de commencer")
    args = ap.parse_args()

    det, rng = load_model(), np.random.default_rng()
    db.init_db()
    with db.connect() as conn:
        if args.reset:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM traffic")
        db.set_meta(conn, "demo", "1")  # flux simules : le bandeau reste affiche
    print("Moteur lance (trafic simule). Ctrl+C pour arreter.")
    start = time.time()
    try:
        while not args.seconds or time.time() - start < args.seconds:
            now = datetime.now(timezone.utc).replace(microsecond=0)
            with db.connect() as conn:
                n = process(conn, det, next_flows(rng), now, enrich=False)  # flux simules : pas d'AbuseIPDB
            if n:
                print(now.strftime("%H:%M:%S"), "->", n, "alerte(s)")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArret.")


if __name__ == "__main__":
    main()
