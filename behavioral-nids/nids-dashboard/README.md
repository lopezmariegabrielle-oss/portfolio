# Behavioral NIDS : API Flask + dashboard

MVP de la partie web du projet : une API Flask à 3 endpoints qui lit une base SQLite, et un dashboard (cartes, graphique, tableau).

## Lancer

```bash
pip install -r requirements.txt
python seed_demo.py          # données de DÉMONSTRATION (fausses, signalées par un bandeau)
python app.py                # http://127.0.0.1:5000
```

Option : `python seed_demo.py --live` (dans un 2e terminal) ajoute du trafic chaque seconde pour voir le dashboard bouger.
Variables : `NIDS_DB` (chemin de la base), `NIDS_HOST` (défaut `127.0.0.1`), `NIDS_PORT` (défaut `5000`).

## Les 3 endpoints

| Route | Alimente | Paramètres |
|---|---|---|
| `GET /api/stats` | les cartes + pastilles de sévérité | aucun |
| `GET /api/traffic` | le graphique (1 point par minute, minutes vides = 0) | `minutes` 5..1440 (défaut 60) |
| `GET /api/alerts` | le tableau | `limit` 1..200 (défaut 50), `offset`, `severity` = low/medium/high/critical |

Paramètre non numérique ou sévérité inconnue → `400` JSON. Valeur hors bornes → ramenée dans les bornes.

## Brancher ton moteur d'analyse

L'API ne fait que lire. Ton moteur Python écrit via `db.py` :

```python
import db
from datetime import datetime, timezone

now = datetime.now(timezone.utc)
with db.connect() as conn:
    db.add_traffic(conn, now.strftime("%Y-%m-%dT%H:%M:00Z"), flows=120, anomalies=1)
    db.insert_alert(conn, now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    src_ip="203.0.113.7", dst_ip="192.168.1.10", score=0.93,
                    dst_port=22, proto="TCP", reason="Rafale SSH inhabituelle")
```

La sévérité est déduite du score (≥0.9 critique, ≥0.75 élevée, ≥0.6 moyenne, sinon faible), sauf si tu la passes toi-même.
Pour passer en vraies données : lance ton moteur sur une base neuve (sans `seed_demo.py`), le bandeau « démonstration » disparaît.

## Sécurité intégrée

- Requêtes SQL toutes paramétrées ; paramètres validés (liste blanche pour la sévérité).
- CSP stricte (scripts/styles uniquement `self`, aucun inline), `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store` sur `/api`.
- Front : `textContent` uniquement (jamais `innerHTML`) : une raison d'alerte contenant du HTML ne s'exécute pas.
- Écoute sur `127.0.0.1` par défaut, `debug` désactivé. Pas d'authentification : à ajouter avant toute exposition réseau.

## Tests

`python -m pytest` (13 tests : formes de réponse, bornes, injections SQL, en-têtes).

## Reste à faire

Capture réseau réelle, extraction de features par flux, modèle ML (ex. Isolation Forest) qui produit le `score`, authentification, WebSocket/SSE à la place du rafraîchissement toutes les 5 s.
