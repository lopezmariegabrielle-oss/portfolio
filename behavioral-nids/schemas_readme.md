## Architecture

```mermaid
flowchart LR
    NET["Trafic réseau<br/>Wi-Fi en0 ou boucle locale lo0"] --> CAP["packet_capture.py<br/>Scapy : adresses, ports, tailles"]
    CAP --> FEAT["feature_extractor.py<br/>4 mesures par IP source et par seconde"]
    FEAT --> MODEL["anomaly_detector.py<br/>Isolation Forest : score et seuil"]
    MODEL --> PIPE["pipeline.py<br/>chef d'orchestre : score vers alerte"]
    REP["reputation.py<br/>AbuseIPDB, facultatif"] -.-> PIPE
    PIPE --> DB[("SQLite reel.db<br/>alerts, traffic, meta")]
    DB --> API["app.py Flask<br/>4 routes"]
    API --> WEB["Navigateur<br/>index.html + app.js"]
```

- **Capture** : Scapy lit les adresses, les ports et les tailles, jamais le contenu des paquets.
- **Mesures** : pour chaque IP source et chaque seconde, nombre de paquets, d'octets, de ports distincts et d'IP distinctes.
- **Modèle** : Isolation Forest (non supervisé). Un score négatif sous le seuil déclenche une alerte.
- **Base et API** : le pipeline écrit dans SQLite, l'API Flask lit la base, le navigateur lit l'API toutes les 5 secondes.

## Diagramme de base de données

```mermaid
erDiagram
    ALERTS {
        integer id PK
        text ts "date ISO 8601 UTC"
        text src_ip
        text dst_ip
        integer dst_port
        text proto
        real score "entre 0 et 1"
        text severity "low, medium, high, critical"
        text reason
        text status "new, investigating, false_positive, resolved"
        integer reputation_score "AbuseIPDB 0 a 100"
        text country
    }
    TRAFFIC {
        text minute PK "debut de minute UTC"
        integer flows
        integer anomalies
    }
    META {
        text key PK
        text value "demo : 0 reel, 1 demonstration"
    }
```

Les trois tables sont indépendantes (pas de clé étrangère) : l'alerte contient directement l'adresse IP, `traffic` alimente le graphique (une ligne par minute) et `meta` garde des réglages.

Conception initiale (`database.py`, conservée et testée, non utilisée par le pipeline) :

```mermaid
erDiagram
    HOSTS ||--o{ ALERTS_INITIAL : "une machine, plusieurs alertes"
    HOSTS {
        text ip PK
        text first_seen
        text last_seen
        integer is_active
    }
    ALERTS_INITIAL {
        integer id PK
        text src_ip FK
        text anomaly_type
        real score
        text status
    }
```
