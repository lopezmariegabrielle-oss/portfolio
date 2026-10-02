from scapy.all import sniff, IP, TCP, UDP
from scapy.error import Scapy_Exception
from datetime import datetime


class PacketCapture:
    """Capture les paquets réseau, les affiche et les garde en mémoire."""

    def __init__(self, interface="en0"):
        self.interface = interface
        self.is_running = False
        self.captured_packets = []  # liste des métriques extraites

    def start_capture(self, packet_count=0):
        """Démarre la capture. packet_count=0 signifie une capture infinie
        (arrêt avec Ctrl+C). Gère les erreurs de permissions et d'interface
        manquante avec des messages clairs."""
        self.is_running = True
        print(f"Capture démarrée sur l'interface {self.interface}...")
        print("Appuie sur Ctrl+C pour arrêter.\n")

        try:
            sniff(
                iface=self.interface,
                prn=self.on_packet_received,
                count=packet_count,
                store=False,
            )
        except Scapy_Exception as e:
            print(
                "\nErreur : droits insuffisants pour capturer les paquets.\n"
                "Relance le script avec : sudo venv/bin/python3 packet_capture.py\n"
                f"Détail : {e}"
            )
            self.is_running = False
        except OSError as e:
            print(
                f"\nErreur : impossible d'utiliser l'interface '{self.interface}'.\n"
                f"Vérifie son nom avec : networksetup -listallhardwareports\n"
                f"Détail : {e}"
            )
            self.is_running = False
        except KeyboardInterrupt:
            print("\nCapture interrompue par l'utilisateur.")
            self.is_running = False

    def stop_capture(self):
        self.is_running = False
        print("Capture arrêtée.")

    def on_packet_received(self, packet):
        """Appelée automatiquement par Scapy à chaque paquet capturé.
        Extrait les métriques et les ajoute à self.captured_packets."""
        if IP in packet:
            metrics = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Autre",
                "size": len(packet),
            }
            self.captured_packets.append(metrics)

            print(
                f"[{metrics['timestamp']}] {metrics['src_ip']} → {metrics['dst_ip']} "
                f"| {metrics['protocol']} | {metrics['size']} octets"
            )

    def get_captured_packets(self):
        """Retourne la liste des métriques capturées jusqu'ici."""
        return self.captured_packets


if __name__ == "__main__":
    capture = PacketCapture(interface="en0")
    capture.start_capture(packet_count=20)

    if capture.get_captured_packets():
        print(f"\n{len(capture.get_captured_packets())} paquets stockés en mémoire.")
        print("Exemple du premier paquet stocké :")
        print(capture.get_captured_packets()[0])