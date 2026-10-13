"""Detecteur d'anomalies comportementales : Isolation Forest + calibration du score en 0..1.

Idee : on entraine le modele UNIQUEMENT sur du trafic normal. Un flux qui ressemble peu
a ce qu'il a vu est "facile a isoler" -> score eleve. Aucune signature d'attaque n'est codee.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["duration", "src_bytes", "dst_bytes", "packets", "failed",
            "conn_rate", "distinct_ports", "port_class"]
CLEARLY_ANOMALOUS = 0.75
ALERT_THRESHOLD = 0.6   # au-dessus : on cree une alerte (= severite "medium" ou plus)

REASONS = {
    "distinct_ports": "Balayage de ports : trop de ports differents contactes",
    "conn_rate": "Rafale de connexions depuis une meme source",
    "failed": "Beaucoup de connexions refusees",
    "src_bytes": "Volume sortant anormalement eleve (exfiltration possible)",
    "packets": "Nombre de paquets anormal pour ce flux",
    "duration": "Duree de connexion inhabituelle",
    "dst_bytes": "Volume recu inhabituel",
    "port_class": "Port de destination inhabituel",
}


def to_matrix(flows):
    """Transforme une liste de flux en tableau numerique (les grandes valeurs passent en log)."""
    rows = []
    for f in flows:
        rows.append([
            np.log1p(f["duration"]), np.log1p(f["src_bytes"]), np.log1p(f["dst_bytes"]),
            np.log1p(f["packets"]), float(f["failed"]),
            np.log1p(f["conn_rate"]), np.log1p(f["distinct_ports"]),
            0.0 if f["dst_port"] in (22, 53, 80, 123, 443, 993) else 1.0,
        ])
    return np.array(rows)


class Detector:
    def __init__(self, seed=0):
        self.forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed)
        self.mean = self.std = None
        self.p50 = self.thr = None

    def fit(self, normal_flows):
        X = to_matrix(normal_flows)
        self.mean, self.std = X.mean(axis=0), X.std(axis=0) + 1e-9
        self.forest.fit(X)
        raw = -self.forest.score_samples(X)
        self.p50 = float(np.percentile(raw, 50))
        self.thr = float(np.percentile(raw, 99.5))  # 0,5 % du trafic normal depasse ce seuil
        return self

    def _scale(self, raw):
        """Echelle lisible : 0 = tres normal, 0.6 = seuil d'alerte, 1 = tres anormal."""
        span = max(self.thr - self.p50, 1e-6)
        low = 0.6 * np.clip((raw - self.p50) / span, 0, 1)
        # 0,75 = niveau "nettement anormal" de l'Isolation Forest (un score brut vise 1 pour un
        # point isole tout de suite, mais depasse rarement 0,8 en pratique)
        top = max(self.thr + 0.05, CLEARLY_ANOMALOUS)
        high = 0.4 * np.clip((raw - self.thr) / (top - self.thr), 0, 1)
        return np.where(raw < self.thr, low, 0.6 + high)

    def score(self, flows):
        X = to_matrix(flows)
        return np.round(self._scale(-self.forest.score_samples(X)), 2)

    def explain(self, flow):
        """Texte court : la caracteristique la plus eloignee du trafic normal.
        Le port (variable 0/1) n'est cite qu'en dernier recours : son ecart-type est minuscule."""
        z = np.abs((to_matrix([flow])[0] - self.mean) / self.std)
        main = z[:-1]
        i = int(np.argmax(main)) if main.max() > 3 else len(FEATURES) - 1
        return REASONS[FEATURES[i]]
