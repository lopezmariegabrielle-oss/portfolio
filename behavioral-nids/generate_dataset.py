"""Construit dataset.csv : du trafic NORMAL réel (Wi-Fi) + des scans nmap (boucle locale lo0).

    sudo venv/bin/python3 generate_dataset.py                         # 10 minutes de trafic normal
    sudo venv/bin/python3 generate_dataset.py --normal-seconds 900    # 15 minutes

Pendant la capture normale, utilise ton Mac COMME D'HABITUDE : navigation, vidéo, musique,
messagerie, téléchargements... Plus c'est varié, moins il y aura de fausses alertes.
Ensuite : python3 anomaly_detector.py
"""
import argparse
import csv
import os
import shutil
import subprocess
import threading
import time

from packet_capture import PacketCapture
from feature_extractor import FeatureExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset.csv")
FIELDS = ["packet_count", "total_bytes", "distinct_ports", "distinct_ips", "label"]  # pas d'adresses IP


def give_back_ownership(path):
    """Sous sudo, le fichier créé appartient à root : on le rend à l'utilisateur normal."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and os.path.exists(path) and os.geteuid() == 0:
        os.chown(path, int(uid), int(gid or uid))


def capture_normal_traffic(interface="en0", duration=600):
    print(f"--- Capture du trafic normal pendant {duration} s sur {interface} ---")
    print("Utilise ton Mac comme d'habitude (web, vidéo, musique, messagerie...).")
    print("Ctrl+C une seule fois pour arrêter plus tôt.\n")
    capture = PacketCapture(interface=interface)
    try:
        capture.start_capture(duration=duration)
    except Exception as e:
        raise SystemExit(f"Erreur de capture : {e}\nVérifie l'interface : route get default | grep interface")
    if not capture.is_running:
        raise SystemExit("La capture n'a pas pu démarrer (droits ? nom d'interface ?). Rien n'a été modifié.")
    packets = capture.get_captured_packets()
    print(f"{len(packets)} paquets normaux capturés.\n")
    return packets


def capture_scan_traffic(rounds=8):
    if shutil.which("nmap") is None:
        raise SystemExit("nmap est introuvable. Installe-le avec : brew install nmap")
    print(f"--- Capture de {rounds} scans nmap (sur ton propre Mac, boucle locale lo0) ---")
    all_packets = []

    for i in range(rounds):
        capture = PacketCapture(interface="lo0")
        scan_thread = threading.Thread(
            target=lambda: subprocess.run(
                ["nmap", "-p", "1-1000", "-T4", "127.0.0.1"],
                capture_output=True,
            )
        )
        scan_thread.start()
        capture.start_capture(duration=2)
        scan_thread.join()
        all_packets.extend(capture.get_captured_packets())
        time.sleep(0.5)

    print(f"{len(all_packets)} paquets de scan capturés au total.\n")
    return all_packets


def main():
    ap = argparse.ArgumentParser(description="Construit dataset.csv (trafic normal + scans nmap)")
    ap.add_argument("--interface", default="en0", help="interface du trafic normal (défaut : en0)")
    ap.add_argument("--normal-seconds", type=int, default=600, help="durée de la capture normale (défaut : 600 s)")
    ap.add_argument("--scan-rounds", type=int, default=8, help="nombre de scans nmap (défaut : 8)")
    args = ap.parse_args()

    normal_packets = capture_normal_traffic(args.interface, args.normal_seconds)
    scan_packets = capture_scan_traffic(args.scan_rounds)

    extractor = FeatureExtractor(window_size=1.0)

    normal_features = extractor.build_feature_vectors(normal_packets)
    for f in normal_features:
        f["label"] = "normal"

    scan_features = extractor.build_feature_vectors(scan_packets)
    for f in scan_features:
        f["label"] = "anomaly"

    if os.path.exists(DATASET):
        backup = os.path.join(HERE, "dataset.backup.csv")
        shutil.copy2(DATASET, backup)
        give_back_ownership(backup)
        print(f"Ancien jeu de données conservé dans {backup}")

    with open(DATASET, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(normal_features + scan_features)
    give_back_ownership(DATASET)

    print(f"Jeu de données sauvegardé dans {DATASET}")
    print(f"{len(normal_features)} exemples normaux, {len(scan_features)} exemples anormaux.")
    print("Étape suivante : python3 anomaly_detector.py")


if __name__ == "__main__":
    main()
