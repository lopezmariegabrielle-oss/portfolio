from collections import defaultdict


class FeatureExtractor:
    """Regroupe les paquets par IP source sur des fenêtres de temps,
    et calcule des métriques résumées pour chaque fenêtre."""

    def __init__(self, window_size=1.0):
        self.window_size = window_size

    def build_feature_vectors(self, packets):
        """Prend la liste de paquets (dicts avec epoch, src_ip, dst_ip,
        dst_port, protocol, size) et retourne une liste de vecteurs de
        features, un par (IP source, fenêtre de temps)."""

        windows = defaultdict(list)

        for pkt in packets:
            window_key = (pkt["src_ip"], self._window_index(pkt))
            windows[window_key].append(pkt)

        features = []
        for (src_ip, _), pkts_in_window in windows.items():
            dst_ports = {p.get("dst_port") for p in pkts_in_window if p.get("dst_port")}
            dst_ips = {p["dst_ip"] for p in pkts_in_window}

            features.append({
                "src_ip": src_ip,
                "packet_count": len(pkts_in_window),
                "total_bytes": sum(p["size"] for p in pkts_in_window),
                "distinct_ports": len(dst_ports),
                "distinct_ips": len(dst_ips),
            })

        return features

    def _window_index(self, pkt):
        """Convertit le timestamp du paquet en numéro de fenêtre."""
        return int(pkt["epoch"] / self.window_size)