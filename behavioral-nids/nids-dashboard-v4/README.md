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
| `GET /api/alerts` | le tableau | `limit` 1..200 (défaut 50), `offset`, `severity` = low/medium/high/critical, `status` = new/investigating/false_positive/resolved |
| `PATCH /api/alerts/<id>` | changer le statut d'une alerte (corps JSON `{"status": "resolved"}`) | statuts : `new`, `investigating`, `false_positive`, `resolved` |

Chaque alerte a un **statut** (nouvelle, en cours, fausse alerte, traitée) modifiable dans le tableau : c'est le tri d'un analyste. La carte « Alertes » indique combien restent à traiter. Une base créée avant cet ajout est migrée automatiquement.

Paramètre non numérique ou valeur inconnue (sévérité, statut) → `400` JSON. Valeur hors bornes → ramenée dans les bornes.

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

## Le moteur de détection (dossier `engine/`)

| Fichier | Rôle |
|---|---|
| `simulate.py` | fabrique des flux **simulés** : normaux + 3 attaques (balayage de ports, force brute SSH, exfiltration) |
| `model.py` | Isolation Forest entraîné sur le trafic normal uniquement ; score calibré de 0 à 1 ; explication de l'alerte |
| `train.py` | entraîne et sauvegarde `model.pkl`, affiche fausses alertes / détections |
| `run_detection.py` | boucle : flux → score → alertes et trafic écrits dans la base → visibles sur le dashboard |

```bash
pip install -r requirements.txt
python engine/train.py                       # ~0,5 % de fausses alertes, ~95 % d'attaques détectées (sur données simulées)
python engine/run_detection.py --reset       # 1er terminal : le moteur
python app.py                                # 2e terminal : le dashboard (NIDS_PORT=5001 sur Mac)
```

Le modèle est réel, mais le trafic est simulé : les chiffres de performance ne valent donc que pour ces scénarios simulés, pas pour un vrai réseau.
`pickle` : ne charger que son propre `model.pkl`.

## Capture du vrai trafic (Mac)

Principe : `tcpdump` (déjà installé sur macOS) tourne en administrateur et envoie du texte à `engine/capture.py`, qui tourne avec **tes** droits. Le script reconstitue des flux (adresses, ports, tailles : jamais le contenu, `-s 96` ne capture que les en-têtes), calcule les indicateurs par source, puis note les flux avec le modèle.

1. Trouver l'interface Wi-Fi : `route get default | grep interface` (souvent `en0`).
2. **Apprendre ton trafic normal** : 10 à 15 min d'usage habituel (navigation, vidéo, messagerie), puis Ctrl+C.
   ```bash
   sudo tcpdump -i en0 -l -n -tt -s 96 'ip or ip6' | python engine/capture.py --learn engine/learned_flows.jsonl
   python engine/train.py --from engine/learned_flows.jsonl    # crée engine/model_real.pkl
   ```
3. **Détecter en direct** (+ `NIDS_PORT=5001 python app.py` dans un autre terminal) :
   ```bash
   sudo tcpdump -i en0 -l -n -tt -s 96 'ip or ip6' | python engine/capture.py --live
   ```
   Le bandeau « démonstration » disparaît. Pour repartir d'une base propre : supprimer `nids.db*`.

À savoir : ne capturer que ton propre ordinateur / ton propre réseau. `learned_flows.jsonl` et `nids.db` contiennent des adresses IP : ne pas les publier (ils sont dans `.gitignore`).
Limite honnête : le modèle apprend « ton » normal ; sans vraie attaque à tester, on ne peut pas mesurer le taux de détection sur du trafic réel. Pour une mesure sérieuse, utiliser un jeu de données public étiqueté (ex. CIC-IDS).

## Sécurité intégrée

- Requêtes SQL toutes paramétrées ; paramètres validés (liste blanche pour la sévérité).
- CSP stricte (scripts/styles uniquement `self`, aucun inline), `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store` sur `/api`.
- Front : `textContent` uniquement (jamais `innerHTML`) : une raison d'alerte contenant du HTML ne s'exécute pas.
- Seule écriture de l'API (`PATCH`) : JSON obligatoire, statut en liste blanche, requêtes d'un autre site refusées (contrôle de l'en-tête `Origin`, protection CSRF).
- Écoute sur `127.0.0.1` par défaut, `debug` désactivé. Pas d'authentification : à ajouter avant toute exposition réseau.

## Tests

`python -m pytest` (39 tests : formes de réponse, bornes, injections SQL, en-têtes).

## Reste à faire

Évaluation sur un vrai jeu de données (ex. CIC-IDS), authentification, WebSocket/SSE à la place du rafraîchissement toutes les 5 s.
