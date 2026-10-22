"""Tests du réglage du seuil et de la sauvegarde du modèle (données simulées, aucun réseau)."""
import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from anomaly_detector import AnomalyDetector, FEATURE_COLUMNS, evaluate_thresholds

SCAN = {"packet_count": 500, "total_bytes": 25000, "distinct_ports": 250, "distinct_ips": 1}
VIDEO = {"packet_count": 900, "total_bytes": 1_100_000, "distinct_ports": 1, "distinct_ips": 1}
WEB = {"packet_count": 40, "total_bytes": 20000, "distinct_ports": 1, "distinct_ips": 5}


@pytest.fixture(scope="module")
def csv_path(tmp_path_factory):
    """Jeu de données simulé : beaucoup de trafic normal varié + quelques scans."""
    rng = np.random.default_rng(3)
    rows = []
    for _ in range(2400):                         # petit trafic
        n = int(rng.integers(1, 6))
        rows.append((n, n * int(rng.integers(60, 400)), 1, int(rng.integers(1, 4)), "normal"))
    for _ in range(500):                          # pages web
        n = int(rng.integers(8, 140))
        rows.append((n, n * int(rng.integers(80, 900)), int(rng.integers(1, 3)), int(rng.integers(2, 10)), "normal"))
    for _ in range(180):                          # vidéo / téléchargements
        n = int(rng.integers(150, 1600))
        rows.append((n, n * int(rng.integers(500, 1450)), 1, 1, "normal"))
    for _ in range(12):                           # scans
        n = int(rng.integers(331, 990))
        rows.append((n, n * int(rng.integers(45, 60)), max(2, int(n * rng.uniform(0.3, 0.6))), 1, "anomaly"))
    path = tmp_path_factory.mktemp("data") / "dataset.csv"
    pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"]).sample(frac=1, random_state=1).to_csv(path, index=False)
    return str(path)


def test_le_seuil_conseille_detecte_les_scans_avec_peu_de_fausses_alertes(csv_path):
    suggested, table = evaluate_thresholds(csv_path, show=False)
    row = next(r for r in table if r[0] == suggested)
    assert -0.4 <= suggested <= -0.02
    assert row[2] == pytest.approx(1.0)           # tous les scans de test détectés
    assert row[1] <= 0.02                         # au plus 2 % de fausses alertes


def test_detecteur_entraine_distingue_scan_video_et_web(csv_path):
    suggested, _ = evaluate_thresholds(csv_path, show=False)
    det = AnomalyDetector(threshold=suggested)
    det.train(csv_path)
    assert det.score_to_alert(SCAN)[0] == True
    assert det.score_to_alert(VIDEO)[0] == False   # une vidéo n'est pas une attaque
    assert det.score_to_alert(WEB)[0] == False


def test_sauvegarde_et_chargement_gardent_le_seuil(csv_path, tmp_path):
    det = AnomalyDetector(threshold=-0.17)
    det.train(csv_path)
    det.save(str(tmp_path / "m.joblib"))
    autre = AnomalyDetector(threshold=-0.1)
    autre.load(str(tmp_path / "m.joblib"))
    assert autre.threshold == pytest.approx(-0.17)
    assert autre.predict(SCAN) == pytest.approx(det.predict(SCAN))


def test_ancien_modele_a_4_metriques_reste_utilisable(csv_path, tmp_path):
    """Un model.joblib créé avant l'ajout de 'ports par paquet' doit continuer à marcher."""
    data = pd.read_csv(csv_path)
    ancien = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    ancien.fit(data[FEATURE_COLUMNS])
    joblib.dump(ancien, tmp_path / "old.joblib")
    det = AnomalyDetector()
    det.load(str(tmp_path / "old.joblib"))
    assert det.use_ratio is False
    assert isinstance(det.predict(SCAN), float)


def test_entrainement_sur_trafic_normal_seulement_fonctionne(csv_path):
    det = AnomalyDetector()
    det.train(csv_path, normal_only=True)
    assert det.is_trained is True
