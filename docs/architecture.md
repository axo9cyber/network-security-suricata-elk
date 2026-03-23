# Architecture du Lab — Suricata + ELK

## Vue d'ensemble

Ce lab reproduit un environnement de surveillance réseau professionnel dans un cadre virtualisé et isolé. L'architecture suit le modèle **SIEM (Security Information and Event Management)** avec :

1. Une **sonde IDS** (Suricata) positionnée sur le chemin du trafic réseau
2. Un **pipeline de collecte** (Logstash/Filebeat) qui ingère les alertes
3. Un **moteur d'indexation** (Elasticsearch) pour le stockage et la recherche
4. Une **interface de visualisation** (Kibana) pour l'analyse et les dashboards

---

## Diagramme de flux de données

```
                        RÉSEAU INTERNE LAB (192.168.100.0/24)
 ┌──────────────┐                                    ┌──────────────┐
 │   ATTAQUANT  │                                    │    CIBLE     │
 │  Kali Linux  │                                    │  Ubuntu      │
 │ 192.168.100.10│                                   │ 192.168.100.30│
 └──────┬───────┘                                    └──────┬───────┘
        │  Trafic réseau (TCP/UDP/ICMP)                     │
        └───────────────────┬───────────────────────────────┘
                            │
                   ┌────────▼────────┐
                   │   SURICATA IDS  │  ← Écoute en mode passif (promiscuité)
                   │  192.168.100.20 │
                   │                 │
                   │  Analyse des    │
                   │  paquets en     │
                   │  temps réel     │
                   └────────┬────────┘
                            │
                     eve.json (alertes)
                            │
                   ┌────────▼────────┐
                   │    LOGSTASH     │
                   │                 │
                   │ • Lecture fichier│
                   │ • Parse JSON    │
                   │ • Enrichit GeoIP│
                   │ • Normalise ECS │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │ ELASTICSEARCH   │
                   │                 │
                   │ • Index mapping │
                   │ • Stockage logs │
                   │ • Recherche FTS │
                   │ • ILM (rotation)│
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │    KIBANA       │
                   │                 │
                   │ • Dashboards    │
                   │ • Discover      │
                   │ • Alerting      │
                   │ • Maps GeoIP    │
                   └─────────────────┘
```

---

## Composants détaillés

### Suricata IDS

**Rôle** : Analyse passive du trafic réseau pour détecter les menaces

**Mode de déploiement** : Mode IDS (détection uniquement, pas de blocage)

**Positionnement réseau** : La VM Suricata est connectée au réseau interne avec la carte réseau en mode **promiscuité** (promiscuous mode), ce qui lui permet de capturer tout le trafic du segment, pas uniquement le sien.

**Sources de règles** :
- `suricata.rules` : Règles Emerging Threats Open (mise à jour automatique)
- `local.rules` : Règles personnalisées pour les scénarios du lab

**Output principal** : `/var/log/suricata/eve.json`

Le format EVE (Extensible Event Format) est un JSON structuré contenant :
- Alertes IDS avec signature et sévérité
- Métadonnées de flux (src/dst IP, ports, protocole)
- Données applicatives (HTTP, DNS, TLS, SSH...)

---

### Pipeline Logstash

**Rôle** : Collecte, transformation et enrichissement des logs Suricata

**Étapes du pipeline** :

```
Input (file/beats)
    ↓
Filter 1 : Parse JSON (codec json)
    ↓
Filter 2 : Date parsing (@timestamp)
    ↓
Filter 3 : Rename fields (ECS compatibility)
    ↓
Filter 4 : GeoIP enrichment (src/dst IP)
    ↓
Filter 5 : Severity label mapping
    ↓
Filter 6 : Event metadata (kind, category, module)
    ↓
Filter 7 : Cleanup (remove unused fields)
    ↓
Output → Elasticsearch (index dynamique)
```

**Schéma d'indexation** :
- `suricata-alert-YYYY.MM.DD` : Alertes IDS
- `suricata-http-YYYY.MM.DD` : Flux HTTP
- `suricata-dns-YYYY.MM.DD` : Requêtes DNS
- `suricata-tls-YYYY.MM.DD` : Sessions TLS
- `suricata-ssh-YYYY.MM.DD` : Sessions SSH

---

### Elasticsearch

**Rôle** : Stockage, indexation et recherche full-text des événements

**Configuration** :
- Nœud unique (single-node cluster) pour le lab
- Sécurité désactivée (lab isolé)
- ILM (Index Lifecycle Management) pour la rotation des index
- Template de mapping personnalisé pour les champs Suricata

**Mapping important** :
- `source.ip` / `destination.ip` → type `ip` (pour les recherches CIDR)
- `source.geo.location` → type `geo_point` (pour les cartes)
- `@timestamp` → type `date` (axe temporel des dashboards)
- `alert.signature` → type `text` + `keyword` (recherche et agrégation)

---

### Kibana

**Rôle** : Visualisation, exploration et alerting

**Dashboards créés** :

| Dashboard | Description |
|-----------|-------------|
| Network Overview | Vue d'ensemble en temps réel |
| Alert Analysis | Analyse détaillée des alertes IDS |
| Traffic Baseline | Profil du trafic normal |
| Threat Hunting | Exploration des IOCs |

**Fonctionnalités utilisées** :
- **Discover** : Exploration des logs bruts
- **Lens** : Création de visualisations
- **Maps** : Cartographie des sources d'attaque
- **Alerting** : Notifications sur seuils

---

## Flux de détection — Exemple complet

### Scénario : Nmap SYN scan depuis Kali

```
[1] Kali Linux exécute : nmap -sS 192.168.100.30

[2] Paquets SYN envoyés vers 192.168.100.30 sur 65535 ports

[3] Suricata capture les paquets (mode promiscuité)
    → Moteur de détection compare avec les règles
    → Règle LAB-SCAN SYN Scan (SID 9000001) déclenchée
    → Seuil : 20 SYN en 2 secondes

[4] Suricata écrit dans eve.json :
    {
      "timestamp": "2024-01-15T14:23:01.123456",
      "event_type": "alert",
      "src_ip": "192.168.100.10",
      "dest_ip": "192.168.100.30",
      "proto": "TCP",
      "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 9000001,
        "rev": 1,
        "signature": "LAB-SCAN Possible SYN Scan Detected",
        "category": "Attempted Information Leak",
        "severity": 2
      }
    }

[5] Logstash lit eve.json
    → Parse le JSON
    → Ajoute GeoIP (si IP externe)
    → Ajoute severity_label: "Medium"
    → Envoie vers Elasticsearch : suricata-alert-2024.01.15

[6] Kibana affiche l'alerte dans le dashboard
    → Compteur d'alertes mis à jour
    → IP source 192.168.100.10 apparaît dans "Top Source IPs"
    → Timeline montre le pic d'activité à 14:23
```

---

## Considérations de sécurité

Ce lab est conçu pour un **environnement totalement isolé**. En environnement de production, les mesures supplémentaires seraient :

- Activation de la sécurité Elasticsearch (X-Pack)
- TLS sur toutes les communications ELK
- Authentification Kibana
- Chiffrement des volumes Docker
- Rotation automatique des clés
- Sauvegardes régulières des index Elasticsearch
- Mode IPS (inline) pour Suricata avec blocage actif
