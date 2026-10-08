import subprocess
import time
import csv

from packet_capture import PacketCapture
from feature_extractor import FeatureExtractor


def capture_normal_traffic(duration=30):
    print(f"--- Capture du trafic normal pendant {duration}s (navigue normalement) ---")
    capture = PacketCapture(interface="en0")
    capture.start_capture(duration=duration)
    print(f"{len(capture.get_captured_packets())} paquets normaux capturés.\n")
    return capture.get_captured_packets()


def capture_scan_traffic(rounds=8):
    print(f"--- Capture de {rounds} scans nmap ---")
    import threading
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
    normal_packets = capture_normal_traffic(duration=30)
    scan_packets = capture_scan_traffic(rounds=8)

    extractor = FeatureExtractor(window_size=1.0)

    normal_features = extractor.build_feature_vectors(normal_packets)
    for f in normal_features:
        f["label"] = "normal"

    scan_features = extractor.build_feature_vectors(scan_packets)
    for f in scan_features:
        f["label"] = "anomaly"

    all_features = normal_features + scan_features

    with open("dataset.csv", "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["src_ip", "packet_count", "total_bytes",
                        "distinct_ports", "distinct_ips", "label"],
        )
        writer.writeheader()
        writer.writerows(all_features)

    print(f"Jeu de données sauvegardé dans dataset.csv")
    print(f"{len(normal_features)} exemples normaux, {len(scan_features)} exemples anormaux.")


if __name__ == "__main__":
    main()