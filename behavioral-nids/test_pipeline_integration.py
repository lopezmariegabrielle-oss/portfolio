"""Tests d'integration bout-en-bout : faux paquets -> FeatureExtractor -> AnomalyDetector
-> base SQLite du dashboard -> API Flask.

Aucun droit administrateur ni acces reseau necessaire : on injecte de faux paquets.
Lancer :  pytest test_pipeline_integration.py -v
"""
import os
import re
import signal
import time

import pytest

import pipeline
from anomaly_detector import AnomalyDetector
from pipeline import Pipeline, db, to_dashboard_score

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 1_760_000_000.0   # date fixe : tous les paquets sont dans la meme fenetre d'1 s
SCANNER, MAC, SERVEUR = "203.0.113.50", "192.168.1.20", "198.51.100.7"


# ----------------------------------------------------------------- outils
def pkt(epoch, src, dst, port, size, proto="TCP"):
    return {"epoch": epoch, "src_ip": src, "dst_ip": dst, "dst_port": port,
            "protocol": proto, "size": size}


def normal_traffic(base=BASE):
    """15 paquets vers un seul port : une connexion web banale."""
    return [pkt(base + i * 0.01, MAC, SERVEUR, 443, 533) for i in range(15)]


def port_scan(base=BASE, src=SCANNER):
    """500 paquets vers 300 ports differents en moins d'une seconde."""
    return [pkt(base + i * 0.001, src, MAC, 1 + (i % 300), 40) for i in range(500)]


class FakeReputation:
    enabled = True

    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    def enrich(self, src, dst):
        self.calls.append((src, dst))
        if self.error:
            raise self.error
        return self.result


class FakeCapture:
    """Remplace PacketCapture : fournit des paquets sans Scapy ni sudo."""
    def __init__(self, packets, works=True):
        self.packets, self.is_running = packets, works

    def start_capture(self, duration=None):
        pass

    def get_captured_packets(self):
        return self.packets


@pytest.fixture(scope="module")
def detector():
    d = AnomalyDetector(threshold=-0.1)
    d.train(os.path.join(HERE, "dataset.csv"))
    return d


@pytest.fixture
def pipe(detector, tmp_path):
    p = Pipeline(detector, str(tmp_path / "test.db"))
    p.prepare()
    return p


def alerts_of(pipe):
    with db.connect(pipe.db_path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY id")]


def traffic_of(pipe):
    with db.connect(pipe.db_path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM traffic")]


# ------------------------------------------------------------ pipeline
def test_trafic_normal_ne_cree_aucune_alerte(pipe):
    assert pipe.process_packets(normal_traffic(), now=BASE) == 0
    assert alerts_of(pipe) == []
    t = traffic_of(pipe)
    assert t[0]["flows"] == 1 and t[0]["anomalies"] == 0


def test_scan_de_ports_cree_une_alerte_complete(pipe):
    assert pipe.process_packets(port_scan(), now=BASE) == 1
    a = alerts_of(pipe)[0]
    assert a["src_ip"] == SCANNER and a["dst_ip"] == MAC
    assert a["proto"] == "TCP" and a["status"] == "new"
    assert 0.6 <= a["score"] <= 1.0
    assert a["severity"] in ("medium", "high", "critical")
    assert a["reason"].startswith("Balayage de ports probable")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", a["ts"])
    assert a["reputation_score"] is None      # pas de client AbuseIPDB


def test_trafic_mixte_une_seule_alerte_et_statistiques(pipe):
    assert pipe.process_packets(normal_traffic() + port_scan(), now=BASE) == 1
    assert [a["src_ip"] for a in alerts_of(pipe)] == [SCANNER]
    t = traffic_of(pipe)[0]
    assert (t["flows"], t["anomalies"]) == (2, 1)


def test_la_base_est_marquee_comme_reelle(pipe):
    with db.connect(pipe.db_path) as c:
        assert db.get_meta(c, "demo") == "0"


def test_aucun_paquet_ne_fait_rien(pipe):
    assert pipe.process_packets([], now=BASE) == 0 and traffic_of(pipe) == []


# -------------------------------------------------------------- AbuseIPDB
def test_reputation_ajoutee_a_l_alerte(detector, tmp_path):
    rep = FakeReputation({"reputation_score": 91, "country": "RU"})
    p = Pipeline(detector, str(tmp_path / "r.db"), reputation=rep)
    p.prepare()
    p.process_packets(port_scan(), now=BASE)
    a = alerts_of(p)[0]
    assert (a["reputation_score"], a["country"]) == (91, "RU")
    assert rep.calls == [(SCANNER, MAC)]


def test_reputation_en_panne_ne_bloque_pas_l_alerte(detector, tmp_path):
    p = Pipeline(detector, str(tmp_path / "e.db"), reputation=FakeReputation(error=OSError("coupé")))
    p.prepare()
    assert p.process_packets(port_scan(), now=BASE) == 1
    assert alerts_of(p)[0]["reputation_score"] is None


def test_reputation_non_appelee_pour_le_trafic_normal(detector, tmp_path):
    rep = FakeReputation({"reputation_score": 1, "country": "FR"})
    p = Pipeline(detector, str(tmp_path / "n.db"), reputation=rep)
    p.prepare()
    p.process_packets(normal_traffic(), now=BASE)
    assert rep.calls == []


def test_le_nombre_de_consultations_abuseipdb_est_plafonne(detector, tmp_path):
    rep = FakeReputation({"reputation_score": 50, "country": "FR"})
    p = Pipeline(detector, str(tmp_path / "cap.db"), reputation=rep)
    p.prepare()
    packets = []
    for n in range(8):                       # 8 scanneurs differents dans la meme tranche
        packets += port_scan(src=f"203.0.113.{n + 1}")
    assert p.process_packets(packets, now=BASE) == 8       # toutes les alertes sont gardees...
    assert len(rep.calls) == pipeline.MAX_LOOKUPS_PER_BATCH  # ...mais AbuseIPDB est plafonne


# ----------------------------------------------------- conversion du score
def test_conversion_du_score():
    assert to_dashboard_score(-0.1, -0.1) == 0.6      # au seuil : moyenne
    assert to_dashboard_score(-0.2, -0.1) == 0.8      # a mi-chemin : elevee
    assert to_dashboard_score(-0.3, -0.1) == 1.0      # tres anormal : critique
    assert to_dashboard_score(-0.9, -0.1) == 1.0      # jamais au-dessus de 1
    assert to_dashboard_score(0.2, -0.1) == 0.6       # jamais en dessous de 0.6


# ------------------------------------------------------------ boucle live
def test_boucle_live_avec_fausse_capture(pipe):
    ok = pipeline.run_live(pipe, iterations=2,
                           capture_factory=lambda iface: FakeCapture(port_scan()))
    assert ok is True and len(alerts_of(pipe)) == 2


def test_boucle_live_s_arrete_si_la_capture_echoue(pipe):
    ok = pipeline.run_live(pipe, iterations=3,
                           capture_factory=lambda iface: FakeCapture([], works=False))
    assert ok is False and alerts_of(pipe) == []


def test_boucle_live_gere_une_erreur_inattendue_de_capture(pipe, capsys):
    class Casse(FakeCapture):
        def start_capture(self, duration=None):
            raise ValueError("Interface 'nope0' not found !")

    ok = pipeline.run_live(pipe, capture_factory=lambda iface: Casse([]))
    assert ok is False
    assert "Erreur de capture" in capsys.readouterr().out


def test_ctrl_c_arrete_la_boucle_proprement(pipe, capsys):
    """Ctrl+C pendant une capture : la tranche en cours est analysee, puis la boucle s'arrete."""
    class CaptureQuiRecoitCtrlC(FakeCapture):
        def start_capture(self, duration=None):
            os.kill(os.getpid(), signal.SIGINT)   # comme si Marie appuyait sur Ctrl+C

    ancien = signal.getsignal(signal.SIGINT)
    ok = pipeline.run_live(pipe, iterations=0,     # 0 = sans fin : seul Ctrl+C peut l'arreter
                           capture_factory=lambda iface: CaptureQuiRecoitCtrlC(port_scan()))
    assert ok is True and len(alerts_of(pipe)) == 1
    assert "Pipeline arrêté" in capsys.readouterr().out
    assert signal.getsignal(signal.SIGINT) == ancien   # le gestionnaire d'origine est rétabli


# ------------------------------------------------------------ API dashboard
def test_l_api_du_dashboard_expose_l_alerte(detector, tmp_path, monkeypatch):
    rep = FakeReputation({"reputation_score": 88, "country": "NL"})
    p = Pipeline(detector, str(tmp_path / "api.db"), reputation=rep)
    p.prepare()
    base = float(int(time.time()))     # alerte "recente" pour les stats des dernieres 24 h
    p.process_packets(port_scan(base), now=base)

    monkeypatch.setenv("NIDS_DB", p.db_path)
    monkeypatch.setattr(db, "DB_PATH", p.db_path)
    app_module = pytest.importorskip("app", reason="app.py du dashboard introuvable")
    factory = getattr(app_module, "create_app", None)
    flask_app = factory() if factory else getattr(app_module, "app", None)
    if flask_app is None:
        pytest.skip("application Flask introuvable dans app.py")
    c = flask_app.test_client()

    r = c.get("/api/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert data["total"] == 1
    item = data["items"][0]
    assert item["src_ip"] == SCANNER and item["dst_ip"] == MAC
    assert item["severity"] in ("medium", "high", "critical")
    assert (item["reputation_score"], item["country"]) == (88, "NL")

    stats = c.get("/api/stats")
    assert stats.status_code == 200 and stats.get_json()["alerts_24h"] == 1