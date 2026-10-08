import pytest
from anomaly_detector import AnomalyDetector


@pytest.fixture
def trained_detector():
    """Prépare un détecteur déjà entraîné, réutilisé par chaque test."""
    detector = AnomalyDetector(threshold=-0.1)
    detector.train("dataset.csv")
    return detector


def test_model_is_trained_after_train(trained_detector):
    """Après train(), le modèle doit être marqué comme entraîné."""
    assert trained_detector.is_trained is True


def test_predict_raises_if_not_trained():
    """predict() doit refuser de fonctionner si le modèle n'est pas entraîné."""
    detector = AnomalyDetector()
    with pytest.raises(RuntimeError):
        detector.predict({
            "packet_count": 10, "total_bytes": 500,
            "distinct_ports": 1, "distinct_ips": 1,
        })


def test_detects_obvious_port_scan(trained_detector):
    """Un comportement avec énormément de ports distincts doit être
    détecté comme une anomalie (signature typique d'un scan de ports)."""
    port_scan_features = {
        "packet_count": 500,
        "total_bytes": 20000,
        "distinct_ports": 300,
        "distinct_ips": 1,
    }
    is_anomaly, score = trained_detector.score_to_alert(port_scan_features)
    assert is_anomaly == True
    assert score < -0.1


def test_normal_single_connection_is_not_anomaly(trained_detector):
    """Une connexion simple vers un seul port doit être jugée normale."""
    normal_features = {
        "packet_count": 15,
        "total_bytes": 8000,
        "distinct_ports": 1,
        "distinct_ips": 1,
    }
    is_anomaly, score = trained_detector.score_to_alert(normal_features)
    assert is_anomaly == False


def test_score_to_alert_returns_tuple(trained_detector):
    """score_to_alert() doit toujours retourner (bool-like, float)."""
    result = trained_detector.score_to_alert({
        "packet_count": 10, "total_bytes": 500,
        "distinct_ports": 1, "distinct_ips": 1,
    })
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert result[0] in (True, False)
    assert isinstance(result[1], float)