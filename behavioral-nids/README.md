# Behavioral NIDS

Système de détection d'intrusion réseau **comportemental** : il observe le trafic de ton ordinateur, apprend à quoi ressemble un comportement normal et signale ce qui s'en écarte (par exemple un scan de ports). Les alertes s'affichent sur un dashboard web.

```
Capture (Scapy) → Extraction de features → Modèle Isolation Forest → Base SQLite → API Flask → Dashboard
                                                       ↘ réputation de l'IP (AbuseIPDB, facultatif)
```

- **Capture** : Scapy lit les paquets (adresses, ports, tailles). Le contenu des paquets n'est jamais lu.
- **Features** : pour chaque adresse source et chaque seconde : nombre de paquets, d'octets, de ports distincts et d'IP distinctes.
- **Modèle** : Isolation Forest (scikit-learn), non supervisé. Plus le score est négatif, plus le comportement est anormal.
- **Dashboard** : cartes de synthèse, graphique trafic/anomalies, tableau d'alertes avec filtres et statuts (Traiter, Rouvrir…).

Testé sur **macOS** (Wi-Fi `en0`) avec **Python 3.14.6**.

---

## 1. Installation

Pré-requis : macOS, Python 3 installé, un terminal. `nmap` est facultatif (il sert à simuler une attaque) : `brew install nmap`.

```bash
cd ~/Portfolio/behavioral-nids
python3 -m venv venv
source venv/bin/activate              # (venv) doit apparaître au début de la ligne
pip install -r requirements.txt
```

À chaque nouveau terminal, il faut refaire `source venv/bin/activate`.

## 2. Lancer le système

Trouve d'abord le nom de ton interface réseau (souvent `en0` pour le Wi-Fi) :

```bash
route get default | grep interface
```

Ouvre **deux terminaux**, tous deux dans `behavioral-nids` avec `(venv)` activé.

**Terminal 1 : le pipeline** (la capture demande les droits administrateur) :

```bash
sudo venv/bin/python3 pipeline.py --db reel.db --interface en0 --window 5
```

Une ligne s'affiche toutes les 5 secondes : `… paquets analysés -> N alerte(s)`. **Ctrl+C une seule fois** pour arrêter (le pipeline termine la tranche en cours).

| Option | Rôle | Défaut |
|---|---|---|
| `--db` | fichier de base. Un nom relatif désigne un fichier de `nids-dashboard-v4/` | `nids.db` du dashboard |
| `--interface` | interface réseau à écouter | `en0` |
| `--window` | durée d'une tranche de capture (secondes) | `5` |
| `--threshold` | seuil de détection (plus il est proche de 0, plus le système est sensible) | celui enregistré avec le modèle |
| `--no-reputation` | ne pas interroger AbuseIPDB | actif si une clé existe |

**Terminal 2 : le dashboard** :

```bash
cd nids-dashboard-v4
NIDS_DB=reel.db NIDS_PORT=5001 python app.py
```

Ouvre ensuite http://127.0.0.1:5001. Le port 5001 est volontaire : sur Mac, le port 5000 est occupé par AirPlay.

## 3. Mode démonstration (données fictives)

Pour montrer le dashboard sans trafic réel :

```bash
cd nids-dashboard-v4
NIDS_DB=demo.db python seed_demo.py
NIDS_DB=demo.db NIDS_PORT=5001 python app.py
```

Un bandeau « démonstration » signale que les données sont fausses. **Attention : `seed_demo.py` efface les alertes de la base qu'on lui donne. Ne jamais le lancer sur `reel.db`.**

## 4. Simuler une attaque (scan de ports)

Dans le terminal 1, écoute l'interface de bouclage :

```bash
sudo venv/bin/python3 pipeline.py --db reel.db --interface lo0 --window 3
```

Dans un troisième terminal, scanne **ton propre ordinateur uniquement** :

```bash
nmap -p 1-1000 127.0.0.1
```

Une alerte « Balayage de ports probable » apparaît sur le dashboard dans les secondes qui suivent.

## 5. Réputation des adresses (AbuseIPDB, facultatif)

1. Crée un compte gratuit sur abuseipdb.com et génère une clé d'API.
2. Dans le terminal du pipeline :

```bash
   export ABUSEIPDB_API_KEY="ta_clé"
   sudo ABUSEIPDB_API_KEY="$ABUSEIPDB_API_KEY" venv/bin/python3 pipeline.py --db reel.db --interface en0
```

   (`sudo` ne transmet pas les variables d'environnement : il faut donc les rappeler dans la commande.)

La colonne « Réputation » affiche alors un score de 0 (sain) à 100 (très signalé) et le pays. Seules les adresses **publiques** sont envoyées ; les adresses de ton réseau local ne le sont jamais. Les réponses sont gardées 24 h en mémoire et le module reste sous la limite du plan gratuit (1000 requêtes par jour). Sans clé, tout fonctionne sauf cette colonne.

**Ne jamais écrire la clé dans le code, dans un fichier versionné ou dans un message.**

## 6. Entraîner / réentraîner le modèle

Le modèle apprend ce qu'est ton trafic « normal ». **Plus ce trafic est long et varié, moins il y a de fausses alertes.** Un modèle appris sur quelques secondes d'inactivité déclenche des alertes sur n'importe quelle vidéo.

```bash
sudo venv/bin/python3 generate_dataset.py     # 10 min de trafic normal + 8 scans nmap -> dataset.csv
python3 anomaly_detector.py                   # évalue, choisit le seuil, entraîne, sauvegarde model.joblib
```

Pendant les 10 minutes de capture, utilise ton Mac comme d'habitude (navigation, vidéo, musique, messagerie, téléchargements). L'ancien `dataset.csv` est conservé dans `dataset.backup.csv`.

`anomaly_detector.py` affiche un tableau de mesures faites sur des exemples **non vus pendant l'entraînement** : pour chaque seuil, le pourcentage de fausses alertes sur du trafic normal et le pourcentage de scans détectés. Il retient automatiquement un seuil conseillé et l'enregistre avec le modèle. Le modèle utilise les 4 métriques de `FeatureExtractor` plus une cinquième calculée : le nombre de ports par paquet (un scan touche énormément de ports avec peu de paquets chacun, une vidéo n'en touche qu'un).

`model.joblib` dépend de la version de scikit-learn : si tu changes de version, relance l'entraînement.

## 7. Tests

```bash
pytest test_pipeline_integration.py test_alert_repository.py test_anomaly_detector.py test_threshold_evaluation.py -v
cd nids-dashboard-v4 && python -m pytest
```

Les tests d'intégration (`test_pipeline_integration.py`) font passer de faux paquets dans toute la chaîne (extraction → modèle → base → API du dashboard). Ils n'ont besoin ni de `sudo`, ni du réseau. Ils vérifient aussi que l'arrêt par Ctrl+C et les erreurs de capture sont gérés.

## 8. Organisation du dépôt

| Fichier / dossier | Rôle |
|---|---|
| `packet_capture.py` | capture Scapy (classe `PacketCapture`) |
| `feature_extractor.py` | regroupe les paquets par source et par seconde, calcule les features |
| `anomaly_detector.py` | modèle Isolation Forest (entraînement, score, évaluation et choix du seuil) |
| `pipeline.py` | enchaîne capture → modèle → base du dashboard (+ AbuseIPDB) |
| `reputation.py` | client AbuseIPDB (cache, limite quotidienne, aucune exception qui remonte) |
| `generate_dataset.py` | construit `dataset.csv` (trafic normal capturé + scans nmap), sans adresses IP |
| `database.py`, `alert_repository.py` | accès SQLite de la conception initiale (voir §10) |
| `nids-dashboard-v4/` | API Flask + dashboard web (voir son propre `README.md`) |
| `test_*.py` | tests unitaires et d'intégration |

## 9. Dépannage

| Problème | Cause | Solution |
|---|---|---|
| `pytest: command not found` | environnement virtuel non activé | `source venv/bin/activate` |
| `sudo: venv/bin/python3: command not found` | mauvais dossier | se placer dans `behavioral-nids` |
| Page « 403 » sur le port 5000 | AirPlay occupe ce port | `NIDS_PORT=5001` |
| « Erreur de capture » | mauvais nom d'interface ou droits manquants | `route get default \| grep interface` et utiliser `sudo` |
| `CERTIFICATE_VERIFY_FAILED` | Python de python.org sans certificats | `open "/Applications/Python 3.14/Install Certificates.command"` ou `pip install certifi` |
| Alertes en double | deux captures tournent en même temps | `pgrep -fl "pipeline.py\|capture.py"` puis arrêter l'une |
| Le dashboard n'arrive pas à écrire (`readonly database`) | fichier de base créé par `sudo` | `sudo chown $USER nids-dashboard-v4/reel.db*` |
| Bandeau « démonstration » toujours affiché | la base contient des données fictives | utiliser une base neuve (`--db reel.db`) |
| Impossible de réécrire `dataset.csv` | fichier créé par `sudo` | `sudo chown $USER dataset.csv` |

## 10. Limites connues et écarts avec la conception

- **Jeu de données propre à une machine** : le modèle apprend « ton » trafic normal et quelques scans de ports (`nmap`). Il n'a pas été évalué sur un jeu public étiqueté (par exemple CIC-IDS) ni sur d'autres types d'attaques.
- **Fausses alertes** : après entraînement sur 10 minutes de trafic normal (3 438 exemples), le modèle déclenche 0,29 % de fausses alertes sur des exemples mis de côté, et 2 alertes en 2 min 30 de navigation réelle (contre environ 80 en 70 s avec le premier jeu de données de 34 exemples). Les rares fausses alertes restantes correspondent à de gros pics de trafic venant d'une seule adresse (téléchargement, vidéo). Seuls 6 exemples de scan ont servi à l'entraînement et 3 à l'évaluation : la détection mesurée (100 %) doit être confirmée sur davantage de scans. Le taux se règle avec `--threshold` ou en réentraînant sur plus de trafic.
- **IPv4 uniquement** pour la capture Scapy (les paquets IPv6 ne sont pas analysés).
- **Capture par tranches** : de très courts instants entre deux tranches ne sont pas écoutés.
- **Droits administrateur** : le pipeline entier tourne avec `sudo` parce que Scapy l'exige. Une amélioration serait de séparer la capture (administrateur) de l'analyse (utilisateur normal), comme le fait le moteur tcpdump du dossier `nids-dashboard-v4/engine/`.
- **Dashboard sans authentification** : il n'écoute que sur `127.0.0.1`. À sécuriser avant toute exposition sur un réseau.
- **Écarts avec les documents de conception** : l'interface web et son API ont été développées séparément puis intégrées. Elles utilisent leur propre schéma de base (tables `alerts`, `traffic`, `meta` ; statuts `new`, `investigating`, `false_positive`, `resolved` ; sévérités jusqu'à « critique ») et exposent 4 routes (3 de lecture + 1 de changement de statut). La conception initiale prévoyait les tables `hosts`, `alerts`, `traffic_stats`, la classe `AlertRepository` et 3 endpoints. `database.py` et `alert_repository.py` sont conservés et testés, mais le pipeline écrit directement dans la base du dashboard.

## 11. Confidentialité et sécurité

- Seules des **métadonnées** sont lues (adresses, ports, tailles) ; jamais le contenu des paquets.
- Les fichiers `*.db` contiennent des adresses IP réelles : ne pas les publier. Ils sont exclus du dépôt par `.gitignore`.
- Ne capture que **ton propre ordinateur ou ton propre réseau**, et ne lance des scans que sur ta propre machine.
- `model.joblib` ne doit être chargé que s'il a été créé par toi (le format peut exécuter du code à la lecture).