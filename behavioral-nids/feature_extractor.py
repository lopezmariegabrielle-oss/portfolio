from collections import Counter, defaultdict


class FeatureExtractor:
    """Regroupe les paquets par IP source sur des fenêtres de temps,
    et calcule des métriques résumées pour chaque fenêtre."""

    def __init__(self, window_size=1.0):
        self.window_size = window_size

    def build_feature_vectors(self, packets):
        """Prend la liste de paquets (dicts avec epoch, src_ip, dst_ip,
        dst_port, protocol, size) et retourne une liste de vecteurs de
        features, un par (IP source, fenêtre de temps).

        Les 4 premières métriques servent au modèle. Les clés suivantes
        (window_start, dst_ip, dst_port, protocol) ne servent qu'à décrire
        une alerte : le modèle ne les utilise pas."""

        windows = defaultdict(list)

        for pkt in packets:
            window_key = (pkt["src_ip"], self._window_index(pkt))
            windows[window_key].append(pkt)

        features = []
        for (src_ip, window_index), pkts_in_window in windows.items():
            dst_ports = {p.get("dst_port") for p in pkts_in_window if p.get("dst_port")}
            dst_ips = {p["dst_ip"] for p in pkts_in_window}

            features.append({
                "src_ip": src_ip,
                "packet_count": len(pkts_in_window),
                "total_bytes": sum(p["size"] for p in pkts_in_window),
                "distinct_ports": len(dst_ports),
                "distinct_ips": len(dst_ips),
                # --- pour décrire l'alerte (non utilisé par le modèle) ---
                "window_start": window_index * self.window_size,
                "dst_ip": self._most_common(p["dst_ip"] for p in pkts_in_window),
                "dst_port": self._most_common(
                    p.get("dst_port") for p in pkts_in_window if p.get("dst_port")),
                "protocol": self._most_common(p.get("protocol") for p in pkts_in_window),
            })

        return features

    @staticmethod
    def _most_common(values):
        """Valeur la plus fréquente (ou None s'il n'y en a pas)."""
        counts = Counter(values)
        return counts.most_common(1)[0][0] if counts else None

    def _window_index(self, pkt):
        """Convertit le timestamp du paquet en numéro de fenêtre."""
        return int(pkt["epoch"] / self.window_size)