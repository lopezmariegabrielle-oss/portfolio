"""Behavioral NIDS : API Flask (3 endpoints) + dashboard web.

Endpoints :
    GET /api/stats    -> cartes du dashboard
    GET /api/traffic  -> serie temporelle du graphique
    GET /api/alerts   -> lignes du tableau d'alertes
"""
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, render_template, request

import db

SEVERITIES = db.SEVERITIES
STATUSES = db.STATUSES
ISO = "%Y-%m-%dT%H:%M:%SZ"


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime(ISO)


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def int_arg(name, default, lo, hi):
    """Lit un parametre entier de la query string : refuse le non-numerique, borne le reste."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ApiError(f"Parametre '{name}' invalide : entier attendu")
    return max(lo, min(hi, value))


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or db.DB_PATH
    db.init_db(app.config["DB_PATH"])

    def connect():
        return db.connect(app.config["DB_PATH"])

    # ------------------------------------------------------------------ pages
    @app.get("/")
    def index():
        return render_template("index.html")

    # -------------------------------------------------------------- endpoint 1
    @app.get("/api/stats")
    def api_stats():
        now = utcnow()
        since_24h = iso(now - timedelta(hours=24))
        since_1h = iso(now - timedelta(hours=1))
        with connect() as c:
            t = c.execute(
                "SELECT COALESCE(SUM(flows), 0) AS flows, COALESCE(SUM(anomalies), 0) AS anomalies "
                "FROM traffic WHERE minute >= ?", (since_24h,)).fetchone()
            alerts_24h = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= ?", (since_24h,)).fetchone()[0]
            alerts_1h = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= ?", (since_1h,)).fetchone()[0]
            to_review = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= ? AND status IN ('new', 'investigating')",
                (since_24h,)).fetchone()[0]
            by_sev = {s: 0 for s in SEVERITIES}
            for row in c.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts WHERE ts >= ? GROUP BY severity",
                    (since_24h,)):
                by_sev[row["severity"]] = row["n"]
            top = c.execute(
                "SELECT src_ip, COUNT(*) AS n FROM alerts WHERE ts >= ? "
                "GROUP BY src_ip ORDER BY n DESC, src_ip LIMIT 1", (since_24h,)).fetchone()
            last_ts = c.execute("SELECT MAX(ts) FROM alerts").fetchone()[0]
            demo = db.get_meta(c, "demo") == "1"

        flows = t["flows"]
        rate = round(100 * t["anomalies"] / flows, 2) if flows else 0.0
        return jsonify({
            "flows_24h": flows,
            "alerts_24h": alerts_24h,
            "alerts_last_hour": alerts_1h,
            "to_review": to_review,
            "anomaly_rate": rate,
            "by_severity": by_sev,
            "top_source": {"ip": top["src_ip"], "count": top["n"]} if top else None,
            "last_alert_ts": last_ts,
            "demo": demo,
            "generated_at": iso(now),
        })

    # -------------------------------------------------------------- endpoint 2
    @app.get("/api/traffic")
    def api_traffic():
        minutes = int_arg("minutes", 60, 5, 1440)
        now_min = utcnow().replace(second=0)
        start = now_min - timedelta(minutes=minutes - 1)
        with connect() as c:
            rows = c.execute(
                "SELECT minute, flows, anomalies FROM traffic WHERE minute >= ?",
                (iso(start),)).fetchall()
        data = {r["minute"]: (r["flows"], r["anomalies"]) for r in rows}
        points = []
        for i in range(minutes):  # on remplit les minutes sans trafic : courbe continue
            m = iso(start + timedelta(minutes=i))
            flows, anomalies = data.get(m, (0, 0))
            points.append({"minute": m, "flows": flows, "anomalies": anomalies})
        return jsonify({"minutes": minutes, "points": points})

    # -------------------------------------------------------------- endpoint 3
    @app.get("/api/alerts")
    def api_alerts():
        limit = int_arg("limit", 50, 1, 200)
        offset = int_arg("offset", 0, 0, 1_000_000)
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        if severity is not None and severity not in SEVERITIES:
            raise ApiError("Parametre 'severity' invalide")
        if status is not None and status not in STATUSES:
            raise ApiError("Parametre 'status' invalide")

        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        with connect() as c:
            total = c.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
            rows = c.execute(
                "SELECT id, ts, src_ip, dst_ip, dst_port, proto, score, severity, reason, status, "
                "reputation_score, country "
                f"FROM alerts {where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                params + [limit, offset]).fetchall()
        return jsonify({"total": total, "items": [dict(r) for r in rows]})

    # -------------------------------------------------------------- endpoint 4
    @app.patch("/api/alerts/<int:alert_id>")
    def api_alert_update(alert_id):
        """Change le statut d'une alerte (seule ecriture de l'API)."""
        # Protection CSRF : une page d'un autre site ne peut pas envoyer ce type de requete.
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            raise ApiError("Origine refusee", 403)
        if not request.is_json:
            raise ApiError("Content-Type application/json requis", 415)
        body = request.get_json(silent=True)
        status = body.get("status") if isinstance(body, dict) else None
        if status not in STATUSES:
            raise ApiError("Champ 'status' invalide : " + ", ".join(STATUSES))
        with connect() as c:
            cur = c.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            if cur.rowcount == 0:
                raise ApiError("Alerte introuvable", 404)
        return jsonify({"id": alert_id, "status": status})

    # ------------------------------------------------------- erreurs et securite
    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return jsonify({"error": err.message}), err.status

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


if __name__ == "__main__":
    # Par defaut on n'ecoute que sur la machine locale, jamais en mode debug.
    create_app().run(
        host=os.environ.get("NIDS_HOST", "127.0.0.1"),
        port=int(os.environ.get("NIDS_PORT", "5000")),
        debug=False,
    )
