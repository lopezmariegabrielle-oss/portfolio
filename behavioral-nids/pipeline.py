"""Pipeline complet : capture Scapy -> FeatureExtractor -> AnomalyDetector -> base du dashboard.

Lancement (la capture Scapy demande les droits administrateur) :

    sudo ABUSEIPDB_API_KEY="$ABUSEIPDB_API_KEY" venv/bin/python3 pipeline.py --db reel.db

--db reel.db désigne le fichier nids-dashboard-v4/reel.db (le même que celui lu par le dashboard).
La clé AbuseIPDB est facultative : sans elle, tout fonctionne, sans la colonne Réputation.
"""
import argparse
import os
import signal
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.environ.get("NIDS_DASHBOARD_DIR", os.path.join(HERE, "nids-dashboard-v4"))
sys.path.insert(0, DASHBOARD_DIR)
sys.path.insert(0, HERE)  # nos modules passent avant ceux du dashboard

import db  # noqa: E402  (acces SQLite du dashboard)
from anomaly_detector import AnomalyDetector  # noqa: E402
from feature_extractor import FeatureExtractor  # noqa: E402
from reputation import ReputationClient  # noqa: E402

ISO = "%Y-%m-%dT%H:%M:%SZ"
SCORE_SPAN = 0.2        # ecart sous le seuil qui donne le score maximum (1.0)
PORT_SCAN_PORTS = 10    # a partir de ce nombre de ports distincts : "balayage de ports"
MAX_LOOKUPS_PER_BATCH = 5   # consultations AbuseIPDB max par tranche (chacune peut durer jusqu'a 3 s)


# ---------------------------------------------------------------- utilitaires
def to_iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(ISO)


def to_dashboard_score(raw_score, threshold, span=SCORE_SPAN):
    """Convertit le score d'Isolation Forest (negatif = anormal) vers l'echelle 0..1 du dashboard.

    Au seuil de detection -> 0.60 (severite "moyenne").
    `span` sous le seuil ou plus -> 1.00 ("critique"). Entre les deux : proportionnel.
    """
    depth = (threshold - float(raw_score)) / span
    return round(0.6 + 0.4 * min(max(depth, 0.0), 1.0), 2)


def describe(vector, window_size=1.0):
    """Phrase affichee dans la colonne "Raison" du dashboard."""
    base = (f"{vector['packet_count']} paquets, {vector['distinct_ports']} port(s) et "
            f"{vector['distinct_ips']} IP distincts en {window_size:g} s")
    if vector["distinct_ports"] >= PORT_SCAN_PORTS:
        return "Balayage de ports probable : " + base
    return "Comportement inhabituel : " + base


def fix_ownership(path):
    """Sous sudo, rend la base a l'utilisateur normal pour que le dashboard puisse y ecrire."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    for suffix in ("", "-wal", "-shm"):
        f = path + suffix
        if os.path.exists(f):
            os.chown(f, int(uid), int(gid or uid))


def resolve_db_path(value):
    """Un nom relatif (reel.db) designe un fichier du dossier du dashboard."""
    value = value or os.environ.get("NIDS_DB") or db.DB_PATH
    return value if os.path.isabs(value) else os.path.join(DASHBOARD_DIR, value)


# ------------------------------------------------------------------- pipeline
class Pipeline:
    def __init__(self, detector, db_path, extractor=None, reputation=None, clock=time.time):
        self.detector = detector
        self.db_path = db_path
        self.extractor = extractor or FeatureExtractor()
        self.reputation = reputation          # ReputationClient ou None
        self.clock = clock

    def prepare(self):
        """Cree/migre la base et indique au dashboard que les donnees sont reelles."""
        db.init_db(self.db_path)
        with db.connect(self.db_path) as conn:
            fix_ownership(self.db_path)
            db.set_meta(conn, "demo", "0")
        fix_ownership(self.db_path)

    def _enrich(self, vector):
        """Reputation AbuseIPDB de l'IP distante, ou None. Ne doit jamais bloquer le pipeline."""
        if self.reputation is None or not getattr(self.reputation, "enabled", False):
            return None
        try:
            return self.reputation.enrich(vector["src_ip"], vector["dst_ip"])
        except Exception:
            return None

    def process_packets(self, packets, now=None):
        """Analyse un lot de paquets. Renvoie le nombre d'alertes creees."""
        if not packets:
            return 0
        vectors = self.extractor.build_feature_vectors(packets)
        now = self.clock() if now is None else now

        # 1) on decide et on enrichit AVANT d'ouvrir la base (l'appel reseau peut etre lent)
        alerts, lookups = [], 0
        for v in vectors:
            is_anomaly, raw = self.detector.score_to_alert(v)
            if is_anomaly:
                rep = None
                if lookups < MAX_LOOKUPS_PER_BATCH:   # evite de bloquer la capture si beaucoup d'alertes
                    rep = self._enrich(v)
                    lookups += 1
                alerts.append((v, to_dashboard_score(raw, self.detector.threshold), rep))

        # 2) ecriture rapide
        with db.connect(self.db_path) as conn:
            fix_ownership(self.db_path)
            for v, score, rep in alerts:
                db.insert_alert(
                    conn, to_iso(v["window_start"]), v["src_ip"], v["dst_ip"], score,
                    dst_port=v["dst_port"], proto=v["protocol"],
                    reason=describe(v, self.extractor.window_size),
                    reputation_score=rep["reputation_score"] if rep else None,
                    country=rep["country"] if rep else None,
                )
            minute = datetime.fromtimestamp(now, timezone.utc).replace(second=0, microsecond=0)
            db.add_traffic(conn, minute.strftime(ISO), len(vectors), len(alerts))
        fix_ownership(self.db_path)
        return len(alerts)


def run_live(pipeline, interface="en0", window=5.0, iterations=0, capture_factory=None):
    """Capture par tranches de `window` secondes et analyse chaque tranche.

    iterations=0 : tourne jusqu'a Ctrl+C (l'arret a lieu a la fin de la tranche en cours).
    Renvoie False si la capture n'a pas pu demarrer.
    """
    if capture_factory is None:
        from packet_capture import PacketCapture  # import ici : Scapy n'est pas requis pour les tests
        capture_factory = PacketCapture

    # Scapy attrape lui-meme Ctrl+C pendant la capture et rend la main sans prevenir :
    # on pose donc notre propre gestionnaire, qui leve un drapeau verifie a chaque tour.
    stop = {"asked": False}

    def ask_stop(signum, frame):
        stop["asked"] = True
        print("\nArrêt demandé : fin de la tranche en cours...")

    previous = signal.signal(signal.SIGINT, ask_stop)
    try:
        pipeline.prepare()
        done = 0
        while not stop["asked"] and (not iterations or done < iterations):
            capture = capture_factory(interface)
            try:
                capture.start_capture(duration=window)
            except Exception as e:  # interface inconnue, droits manquants...
                print(f"\nErreur de capture : {e}\n"
                      f"Vérifie le nom de l'interface (networksetup -listallhardwareports) "
                      f"et lance le pipeline avec sudo.")
                return False
            if not capture.is_running:  # erreur de droits/interface
                return False
            packets = capture.get_captured_packets()
            alerts = pipeline.process_packets(packets)
            done += 1
            print(f"{time.strftime('%H:%M:%S')}  {len(packets):5d} paquets analysés  ->  {alerts} alerte(s)")
        if stop["asked"]:
            print("Pipeline arrêté.")
        return True
    finally:
        signal.signal(signal.SIGINT, previous)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Pipeline NIDS : capture -> ML -> dashboard")
    ap.add_argument("--interface", default="en0", help="interface reseau (defaut : en0)")
    ap.add_argument("--window", type=float, default=5.0, help="duree d'une tranche de capture, en secondes")
    ap.add_argument("--db", help="fichier de base (nom relatif = dans nids-dashboard-v4)")
    ap.add_argument("--model", default=os.path.join(HERE, "model.joblib"))
    ap.add_argument("--threshold", type=float, default=None,
                    help="seuil de detection (defaut : celui enregistre avec le modele)")
    ap.add_argument("--no-reputation", action="store_true", help="ne pas interroger AbuseIPDB")
    ap.add_argument("--iterations", type=int, default=0, help="nombre de tranches (0 = sans fin)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.model):
        print(f"Modèle introuvable : {args.model}\nCrée-le avec : python3 anomaly_detector.py")
        return 1
    detector = AnomalyDetector()
    detector.load(args.model)
    if args.threshold is not None:
        detector.threshold = args.threshold
        print(f"Seuil forcé à {detector.threshold:+.2f}")

    client = None if args.no_reputation else ReputationClient()
    print("AbuseIPDB :", "activé" if client and client.enabled else "désactivé (pas de clé ABUSEIPDB_API_KEY)")

    db_path = resolve_db_path(args.db)
    print("Base :", db_path)
    pipeline = Pipeline(detector, db_path, reputation=client)
    try:
        ok = run_live(pipeline, args.interface, args.window, args.iterations)
    except KeyboardInterrupt:
        print("\nArrêt demandé.")
        return 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())