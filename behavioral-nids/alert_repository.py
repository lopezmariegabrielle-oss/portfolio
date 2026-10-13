from datetime import datetime

from database import get_connection, DB_PATH

VALID_STATUSES = ("new", "treated", "false_positive")


def compute_severity(score):
    """La gravité est calculée à partir du score, pas stockée en base."""
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


class AlertRepository:
    """Gère l'enregistrement et la lecture des alertes en base."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def save_alert(self, alert):
        """Enregistre une alerte (dict avec src_ip, dst_ip, anomaly_type, score,
        et optionnellement reputation_score, country). Crée l'hôte source
        s'il n'existe pas encore. Retourne l'id de l'alerte créée."""
        now = datetime.now().isoformat(timespec="seconds")
        conn = get_connection(self.db_path)
        try:
            # 1. L'hôte doit exister avant l'alerte (clé étrangère)
            conn.execute(
                "INSERT OR IGNORE INTO hosts (ip, first_seen, last_seen) VALUES (?, ?, ?)",
                (alert["src_ip"], now, now),
            )
            conn.execute(
                "UPDATE hosts SET last_seen = ? WHERE ip = ?",
                (now, alert["src_ip"]),
            )
            # 2. On enregistre l'alerte
            cursor = conn.execute(
                """INSERT INTO alerts
                   (src_ip, dst_ip, timestamp, anomaly_type, score, reputation_score, country)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert["src_ip"],
                    alert["dst_ip"],
                    alert.get("timestamp", now),
                    alert["anomaly_type"],
                    alert["score"],
                    alert.get("reputation_score"),
                    alert.get("country"),
                ),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_alerts(self, filters=None):
        """Retourne la liste des alertes. Filtres possibles (tous facultatifs) :
        severity (high/medium/low), status, sort (date_desc/date_asc), limit."""
        filters = filters or {}
        query = "SELECT * FROM alerts"
        conditions = []
        params = []

        severity = filters.get("severity")
        if severity == "high":
            conditions.append("score >= 0.8")
        elif severity == "medium":
            conditions.append("score >= 0.5 AND score < 0.8")
        elif severity == "low":
            conditions.append("score < 0.5")

        status = filters.get("status")
        if status:
            conditions.append("status = ?")
            params.append(status)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        order = "ASC" if filters.get("sort") == "date_asc" else "DESC"
        query += f" ORDER BY timestamp {order}, id {order}"

        query += " LIMIT ?"
        params.append(int(filters.get("limit", 50)))

        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()

        alerts = []
        for row in rows:
            alert = dict(row)
            alert["severity"] = compute_severity(alert["score"])
            alerts.append(alert)
        return alerts

    def update_status(self, alert_id, new_status):
        """Change le statut d'une alerte. Retourne True si elle existe,
        False sinon (le backend pourra alors répondre 404)."""
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Statut invalide : {new_status}")

        conn = get_connection(self.db_path)
        try:
            cursor = conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (new_status, alert_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()