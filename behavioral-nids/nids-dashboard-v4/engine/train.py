"""Entraine le modele sur du trafic normal simule et le sauvegarde dans engine/model.pkl."""
import os
import pickle
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import simulate  # noqa: E402
from engine.model import ALERT_THRESHOLD, Detector  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "model.pkl")
REAL_PATH = os.path.join(HERE, "model_real.pkl")
MIN_REAL_FLOWS = 300


def evaluate(det, seed=123):
    rng = np.random.default_rng(seed)
    normal = simulate.normal_flows(5000, rng)
    attacks = simulate.attack_flows(1500, rng)
    sn, sa = det.score(normal), det.score(attacks)
    fp = float(np.mean(sn >= ALERT_THRESHOLD))
    tp = float(np.mean(sa >= ALERT_THRESHOLD))
    return fp, tp


def train_real(path):
    """Apprend le trafic normal de TON reseau a partir des flux enregistres par capture.py --learn."""
    import json
    flows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                flows.append(json.loads(line))
            except ValueError:
                continue  # ligne abimee (Ctrl+C en cours d'ecriture) : on l'ignore
    if len(flows) < MIN_REAL_FLOWS:
        sys.exit(f"Seulement {len(flows)} flux : il en faut au moins {MIN_REAL_FLOWS}. "
                 "Laisse la capture tourner plus longtemps en utilisant ton Mac normalement.")
    det = Detector().fit(flows)
    with open(REAL_PATH, "wb") as fh:
        pickle.dump(det, fh)
    print(f"Modele appris sur {len(flows)} flux de ton reseau : {REAL_PATH}")
    print("Pas de mesure de detection possible : tu n'as pas d'attaque reelle a tester (voir README).")


if __name__ == "__main__":
    if "--from" in sys.argv:
        train_real(sys.argv[sys.argv.index("--from") + 1])
        sys.exit(0)
    rng = np.random.default_rng(0)
    det = Detector().fit(simulate.normal_flows(20000, rng))
    with open(PATH, "wb") as fh:
        pickle.dump(det, fh)
    fp, tp = evaluate(det)
    print(f"Modele sauvegarde : {PATH}")
    print(f"Fausses alertes sur trafic normal : {fp:.1%}")
    print(f"Attaques detectees               : {tp:.1%}")
