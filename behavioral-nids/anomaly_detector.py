import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURE_COLUMNS = ["packet_count", "total_bytes", "distinct_ports", "distinct_ips"]


class AnomalyDetector:
    """Entraîne et utilise un modèle Isolation Forest pour détecter
    des comportements réseau anormaux."""

    def __init__(self, threshold=-0.1):
        self.model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
        )
        self.threshold = threshold
        self.is_trained = False

    def train(self, csv_path):
        """Entraîne le modèle à partir du dataset.csv généré précédemment.
        Isolation Forest est non supervisé : on entraîne uniquement sur les
        valeurs numériques, sans jamais lui donner la colonne 'label'."""
        data = pd.read_csv(csv_path)
        X = data[FEATURE_COLUMNS]

        self.model.fit(X)
        self.is_trained = True
        print(f"Modèle entraîné sur {len(data)} exemples.")

    def predict(self, feature_vector):
        """Prend un dict de features (comme ceux produits par
        FeatureExtractor) et retourne un score d'anomalie.
        Plus le score est négatif, plus le comportement est anormal."""
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné avant de faire une prédiction.")

        X = pd.DataFrame([feature_vector])[FEATURE_COLUMNS]
        raw_score = self.model.decision_function(X)[0]
        return raw_score

    def score_to_alert(self, feature_vector):
        """Convertit un vecteur de features en verdict : est-ce une anomalie ?
        Retourne (is_anomaly, score)."""
        score = self.predict(feature_vector)
        is_anomaly = score < self.threshold
        return is_anomaly, score

    def save(self, path="model.joblib"):
        joblib.dump(self.model, path)
        print(f"Modèle sauvegardé dans {path}")

    def load(self, path="model.joblib"):
        self.model = joblib.load(path)
        self.is_trained = True
        print(f"Modèle chargé depuis {path}")


if __name__ == "__main__":
    detector = AnomalyDetector()
    detector.train("dataset.csv")
    detector.save()

    # Test rapide sur un exemple normal et un exemple anormal du dataset
    import pandas as pd
    data = pd.read_csv("dataset.csv")

    print("\n--- Test sur quelques exemples ---")
    for _, row in data.iterrows():
        features = row[FEATURE_COLUMNS].to_dict()
        is_anomaly, score = detector.score_to_alert(features)
        verdict = "ANOMALIE" if is_anomaly else "normal"
        print(f"{row['label']:8s} → prédit: {verdict:8s} (score: {score:.3f})")