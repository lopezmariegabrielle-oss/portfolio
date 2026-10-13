import pytest

from database import create_tables
from alert_repository import AlertRepository


@pytest.fixture
def repo(tmp_path):
    """Base temporaire, supprimée après chaque test (ta vraie base n'est pas touchée)."""
    db_path = str(tmp_path / "test.db")
    create_tables(db_path)
    return AlertRepository(db_path)


def make_alert(score=0.9, src_ip="192.168.1.47"):
    return {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.5",
        "anomaly_type": "Scan port",
        "score": score,
    }


def test_save_and_get_alert(repo):
    alert_id = repo.save_alert(make_alert())
    alerts = repo.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["id"] == alert_id
    assert alerts[0]["status"] == "new"
    assert alerts[0]["severity"] == "high"


def test_save_alert_creates_host(repo):
    repo.save_alert(make_alert(src_ip="192.168.1.99"))
    alerts = repo.get_alerts()
    assert alerts[0]["src_ip"] == "192.168.1.99"


def test_filter_by_severity(repo):
    repo.save_alert(make_alert(score=0.92))
    repo.save_alert(make_alert(score=0.65))
    repo.save_alert(make_alert(score=0.30))
    high = repo.get_alerts({"severity": "high"})
    assert len(high) == 1
    assert high[0]["score"] == 0.92


def test_update_status(repo):
    alert_id = repo.save_alert(make_alert())
    assert repo.update_status(alert_id, "treated") is True
    assert repo.get_alerts({"status": "treated"})[0]["id"] == alert_id


def test_update_status_unknown_alert_returns_false(repo):
    assert repo.update_status(9999, "treated") is False


def test_update_status_invalid_value_raises(repo):
    alert_id = repo.save_alert(make_alert())
    with pytest.raises(ValueError):
        repo.update_status(alert_id, "n_importe_quoi")


def test_sort_order(repo):
    first = repo.save_alert(make_alert())
    second = repo.save_alert(make_alert())
    newest_first = repo.get_alerts({"sort": "date_desc"})
    assert newest_first[0]["id"] == second
    oldest_first = repo.get_alerts({"sort": "date_asc"})
    assert oldest_first[0]["id"] == first