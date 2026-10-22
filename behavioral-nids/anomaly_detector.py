import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# Les 4 métriques produites par FeatureExtractor
FEATURE_COLUMNS = ["packet_count", "total_bytes", "distinct_ports", "distinct_ips"]
# + une métrique calculée ici : un scan touche énormément de ports avec très peu de paquets
# par port, alors qu'une vidéo ou un téléchargement envoie beaucoup de paquets sur un seul port.
RATIO_COLUMN = "ports_per_packet"


def _new_model():
    return IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )


def _model_inputs(frame, use_ratio=True):
    """Colonnes données au modèle (ordre fixe) à partir d'un tableau de features."""
    X = frame[FEATURE_COLUMNS].copy()
    if use_ratio:
        X[RATIO_COLUMN] = X["distinct_ports"] / X["packet_count"].clip(lower=1)
    return X


class AnomalyDetector:
    """Entraîne et utilise un modèle Isolation Forest pour détecter
    des comportements réseau anormaux."""

    def __init__(self, threshold=-0.1):
        self.model = _new_model()
        self.threshold = threshold
        self.use_ratio = True
        self.is_trained = False

    def train(self, csv_path, normal_only=False):
        """Entraîne le modèle à partir du dataset.csv généré précédemment.
        Isolation Forest est non supervisé : on lui donne uniquement les valeurs
        numériques, jamais la colonne 'label'. Avec normal_only=True, on ne lui
        montre que le trafic étiqueté 'normal'."""
        data = pd.read_csv(csv_path)
        if normal_only and "label" in data.columns:
            data = data[data["label"] == "normal"]

        self.model.fit(_model_inputs(data, self.use_ratio))
        self.is_trained = True
        print(f"Modèle entraîné sur {len(data)} exemples.")

    def predict(self, feature_vector):
        """Prend un dict de features (comme ceux produits par
        FeatureExtractor) et retourne un score d'anomalie.
        Plus le score est négatif, plus le comportement est anormal."""
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné avant de faire une prédiction.")

        X = _model_inputs(pd.DataFrame([feature_vector]), self.use_ratio)
        raw_score = self.model.decision_function(X)[0]
        return raw_score

    def score_to_alert(self, feature_vector):
        """Convertit un vecteur de features en verdict : est-ce une anomalie ?
        Retourne (is_anomaly, score)."""
        score = self.predict(feature_vector)
        is_anomaly = score < self.threshold
        return is_anomaly, score

    def save(self, path="model.joblib"):
        """Sauvegarde le modèle ET son seuil (ils vont ensemble)."""
        joblib.dump({"model": self.model, "threshold": self.threshold,
                     "use_ratio": self.use_ratio}, path)
        print(f"Modèle sauvegardé dans {path} (seuil {self.threshold:+.2f})")

    def load(self, path="model.joblib"):
        obj = joblib.load(path)
        if isinstance(obj, dict):                 # format actuel : modèle + seuil
            self.model = obj["model"]
            self.threshold = obj.get("threshold", self.threshold)
            self.use_ratio = obj.get("use_ratio", True)
        else:                                     # ancien format : modèle seul, 4 métriques
            self.model = obj
            self.use_ratio = False
        self.is_trained = True
        print(f"Modèle chargé depuis {path} (seuil {self.threshold:+.2f})")


def evaluate_thresholds(csv_path="dataset.csv", max_false_alarm_rate=0.01, margin=0.02, show=True):
    """Mesure la qualité du modèle sur des exemples qu'il n'a PAS vus pendant l'entraînement :
    20 % du trafic normal et la moitié des scans sont mis de côté.

    Pour chaque seuil possible : % de fausses alertes (trafic normal jugé anormal) et % de scans détectés.
    Seuil conseillé = le moins sensible qui détecte encore tous les scans de test,
    rendu un peu plus sensible (`margin`) pour garder une marge de sécurité."""
    data = pd.read_csv(csv_path)
    normal = data[data["label"] == "normal"]
    anomaly = data[data["label"] != "normal"]
    normal_train, normal_test = train_test_split(normal, test_size=0.2, random_state=42)
    if len(anomaly) >= 4:
        anomaly_train, anomaly_test = train_test_split(anomaly, test_size=0.5, random_state=42)
    else:                                         # trop peu de scans pour en mettre de côté
        anomaly_train, anomaly_test = anomaly, anomaly.iloc[0:0]

    model = _new_model().fit(_model_inputs(pd.concat([normal_train, anomaly_train])))
    s_normal = model.decision_function(_model_inputs(normal_test))
    s_anomaly = (model.decision_function(_model_inputs(anomaly_test))
                 if len(anomaly_test) else np.array([]))

    table = []
    for th in np.round(np.arange(-0.02, -0.41, -0.01), 2):
        false_alarms = float(np.mean(s_normal < th))
        detected = float(np.mean(s_anomaly < th)) if len(s_anomaly) else float("nan")
        table.append((float(th), false_alarms, detected))

    if len(s_anomaly):
        best = max(row[2] for row in table)
        full = [row for row in table if row[2] >= best - 1e-9]
        edge = full[-1][0]                        # seuil le plus négatif qui détecte autant
        suggested = round(min(edge + margin, -0.02), 2)
    else:
        ok = [row for row in table if row[1] <= max_false_alarm_rate]
        suggested = ok[0][0] if ok else table[-1][0]

    if show:
        print(f"\n--- Évaluation sur {len(normal_test)} exemples normaux et "
              f"{len(anomaly_test)} scans que le modèle n'a pas vus ---")
        print("seuil    fausses alertes    scans détectés")
        for th, fa, det in table:
            if th in (-0.05, -0.10, -0.15, -0.20, -0.25, -0.30) or th == suggested:
                mark = "  <- conseillé" if th == suggested else ""
                print(f"{th:+.2f}      {fa * 100:5.2f} %          {det * 100:5.1f} %{mark}")
    return suggested, table


if __name__ == "__main__":
    suggested, table = evaluate_thresholds("dataset.csv")
    chosen = next(row for row in table if row[0] == suggested)
    print(f"\nSeuil retenu : {suggested:+.2f}  "
          f"({chosen[1] * 100:.2f} % de fausses alertes, {chosen[2] * 100:.0f} % des scans détectés)")

    detector = AnomalyDetector(threshold=suggested)
    detector.train("dataset.csv")
    detector.save()