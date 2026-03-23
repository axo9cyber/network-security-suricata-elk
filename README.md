# Network Security Lab — Suricata IDS + ELK Stack

<p align="center">
  <img src="https://img.shields.io/badge/Suricata-IDS%2FIPS-orange?style=for-the-badge&logo=suricata" />
  <img src="https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch" />
  <img src="https://img.shields.io/badge/Kibana-Dashboard-E8478B?style=for-the-badge&logo=kibana" />
  <img src="https://img.shields.io/badge/Logstash-Pipeline-F5A620?style=for-the-badge&logo=logstash" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker" />
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux" />
</p>

> **Déploiement d'un réseau de laboratoire sous surveillance avec Suricata IDS et la pile ELK (Elasticsearch, Logstash, Kibana).**
> Projet de sécurité réseau démontrant la détection d'intrusions, la centralisation des logs et la visualisation d'alertes en temps réel.

---

## Table des matières

- [Aperçu du projet](#-aperçu-du-projet)
- [Architecture réseau](#-architecture-réseau)
- [Technologies utilisées](#-technologies-utilisées)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du projet](#-structure-du-projet)
- [Installation rapide](#-installation-rapide)
- [Configuration Suricata](#-configuration-suricata)
- [Pipeline ELK](#-pipeline-elk)
- [Dashboards Kibana](#-dashboards-kibana)
- [Cas de détection simulés](#-cas-de-détection-simulés)
- [Compétences démontrées](#-compétences-démontrées)

---

## Aperçu du projet

Ce projet met en place un **environnement de surveillance réseau complet** dans un lab virtualisé. L'objectif est de démontrer la capacité à :

- Déployer et configurer **Suricata** comme IDS (Intrusion Detection System)
- Centraliser les alertes et logs dans la **pile ELK**
- Créer des **règles de détection personnalisées**
- Visualiser les incidents de sécurité via **Kibana**
- Simuler des **scénarios d'attaque** pour valider la détection

---

## Architecture réseau

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LAB VIRTUEL (VirtualBox)                     │
│                                                                     │
│   ┌──────────────┐      ┌─────────────────┐      ┌──────────────┐  │
│   │  Attaquant   │      │  IDS / Sonde    │      │   Serveur    │  │
│   │  Kali Linux  │─────►│   Suricata      │─────►│   Cible      │  │
│   │  (VM-1)      │      │   (VM-2)        │      │   (VM-3)     │  │
│   └──────────────┘      └────────┬────────┘      └──────────────┘  │
│                                  │                                  │
│                          Alertes (eve.json)                         │
│                                  │                                  │
│                         ┌────────▼────────┐                        │
│                         │    Logstash     │                        │
│                         │  (Parsing +     │                        │
│                         │   Enrichment)   │                        │
│                         └────────┬────────┘                        │
│                                  │                                  │
│                    ┌─────────────▼──────────────┐                  │
│                    │       Elasticsearch         │                  │
│                    │   (Stockage + Indexation)   │                  │
│                    └─────────────┬──────────────┘                  │
│                                  │                                  │
│                         ┌────────▼────────┐                        │
│                         │     Kibana      │                        │
│                         │  (Dashboards +  │                        │
│                         │  Visualisation) │                        │
│                         └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Réseau interne

| Machine         | OS           | IP              | Rôle                          |
|-----------------|--------------|-----------------|-------------------------------|
| VM-1 (Attaquant)| Kali Linux   | 192.168.100.10  | Génération de trafic malveillant |
| VM-2 (IDS)      | Ubuntu 22.04 | 192.168.100.20  | Suricata + ELK Stack          |
| VM-3 (Cible)    | Ubuntu 22.04 | 192.168.100.30  | Serveur web Apache / SSH      |

---

## Technologies utilisées

| Outil            | Version | Rôle                                    |
|------------------|---------|-----------------------------------------|
| **Suricata**     | 7.x     | IDS/IPS — analyse de trafic réseau      |
| **Elasticsearch**| 8.x     | Moteur de recherche et stockage des logs |
| **Logstash**     | 8.x     | Pipeline d'ingestion et parsing des logs |
| **Kibana**       | 8.x     | Visualisation et dashboards             |
| **Docker**       | 24.x    | Conteneurisation de la pile ELK         |
| **VirtualBox**   | 7.x     | Virtualisation du lab                   |
| **Kali Linux**   | 2024.x  | Plateforme de tests d'intrusion         |

---

## Fonctionnalités

### Detection IDS
- [x] Détection de scans de ports (Nmap, Masscan)
- [x] Détection d'attaques par force brute SSH
- [x] Détection d'activité HTTP suspecte
- [x] Détection de scans de vulnérabilités (Nikto)
- [x] Règles personnalisées pour scénarios spécifiques

### Pipeline de logs
- [x] Collecte des alertes Suricata (`eve.json`)
- [x] Parsing et enrichissement avec Logstash
- [x] Indexation dans Elasticsearch
- [x] Gestion des index avec ILM (Index Lifecycle Management)

### Visualisation
- [x] Dashboard principal — vue d'ensemble des alertes
- [x] Timeline des événements de sécurité
- [x] Top IPs sources malveillantes
- [x] Répartition par catégorie d'attaque
- [x] Carte géographique des sources (GeoIP)

---

## Structure du projet

```
network-security-suricata-elk/
│
├── README.md                         # Ce fichier
│
├── docker-compose.yml                # Stack ELK complète en Docker
│
├── configs/
│   ├── suricata/
│   │   ├── suricata.yaml             # Configuration principale Suricata
│   │   └── local.rules               # Règles de détection personnalisées
│   ├── logstash/
│   │   └── suricata.conf             # Pipeline Logstash pour Suricata
│   └── elasticsearch/
│       └── index-template.json       # Template d'index Elasticsearch
│
├── scripts/
│   ├── setup.sh                      # Script d'installation automatisé
│   └── test-detection.sh             # Script de tests de détection
│
├── docs/
│   ├── installation.md               # Guide d'installation détaillé
│   ├── architecture.md               # Documentation de l'architecture
│   └── suricata-rules.md             # Documentation des règles
│
└── screenshots/
    └── README.md                     # Description des captures d'écran
```

---

## Installation rapide

### Prérequis

- Docker & Docker Compose installés
- Suricata 7.x installé sur la machine sonde
- Minimum 8 Go RAM, 4 vCPU

### 1. Cloner le dépôt

```bash
git clone https://github.com/axo9cyber/network-security-suricata-elk.git
cd network-security-suricata-elk
```

### 2. Démarrer la pile ELK

```bash
docker-compose up -d
```

Vérifier que les services sont en cours d'exécution :

```bash
docker-compose ps
```

### 3. Configurer Suricata

```bash
# Copier la configuration
sudo cp configs/suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo cp configs/suricata/local.rules /etc/suricata/rules/local.rules

# Mettre à jour les règles
sudo suricata-update

# Démarrer Suricata sur l'interface réseau
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

### 4. Configurer Logstash

```bash
sudo cp configs/logstash/suricata.conf /etc/logstash/conf.d/
sudo systemctl restart logstash
```

### 5. Accéder à Kibana

Ouvrir : `http://localhost:5601`

> Guide d'installation complet : [docs/installation.md](docs/installation.md)

---

## Configuration Suricata

Suricata est configuré pour :

- **Mode IDS** en écoute passive sur l'interface réseau
- **Output EVE JSON** vers `/var/log/suricata/eve.json` pour l'ingestion ELK
- **Règles actives** : Emerging Threats Open + règles locales personnalisées

Voir [`configs/suricata/suricata.yaml`](configs/suricata/suricata.yaml) et [`configs/suricata/local.rules`](configs/suricata/local.rules)

---

## Pipeline ELK

```
eve.json (Suricata)
       │
       ▼
  Logstash (port 5044)
  ├─ Filtre : parse JSON
  ├─ Filtre : GeoIP sur src_ip
  ├─ Filtre : enrichissement timestamp
  └─ Output → Elasticsearch
       │
       ▼
  Elasticsearch
  └─ Index : suricata-alerts-YYYY.MM.DD
       │
       ▼
  Kibana
  └─ Dashboard : Network Security Overview
```

Voir [`configs/logstash/suricata.conf`](configs/logstash/suricata.conf)

---

## Dashboards Kibana

### Dashboard principal — Network Security Overview

Le dashboard inclut :

| Visualisation | Description |
|---------------|-------------|
| Alert Timeline | Évolution temporelle des alertes |
| Top Source IPs | IPs générant le plus d'alertes |
| Attack Categories | Répartition par type d'attaque |
| Severity Distribution | Répartition par niveau de sévérité |
| Protocol Breakdown | Répartition par protocole (TCP/UDP/ICMP) |
| GeoIP Map | Carte des origines géographiques |
| Recent Alerts Table | Tableau des dernières alertes en temps réel |

---

## Cas de détection simulés

### 1. Scan de ports (Nmap)

```bash
# Depuis Kali Linux
nmap -sS -p- 192.168.100.30
```

**Règle déclenchée :** `ET SCAN Nmap Scripting Engine User-Agent Detected`

### 2. Force brute SSH (Hydra)

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.100.30 ssh
```

**Règle déclenchée :** `ET BRUTE-FORCE SSH Brute Force Login Attempt`

### 3. Scan de vulnérabilités web (Nikto)

```bash
nikto -h http://192.168.100.30
```

**Règle déclenchée :** `ET SCAN Nikto Web App Vulnerability Scanner`

### 4. Test avec les scripts fournis

```bash
chmod +x scripts/test-detection.sh
./scripts/test-detection.sh
```

---

## Compétences démontrées

| Domaine | Compétences |
|---------|-------------|
| **Sécurité réseau** | Configuration IDS, analyse de trafic, détection d'intrusions |
| **Administration Linux** | Déploiement de services, gestion de configurations |
| **ELK Stack** | Pipeline Logstash, indexation Elasticsearch, Kibana |
| **Docker** | Conteneurisation, orchestration avec Docker Compose |
| **Scripting** | Bash — automatisation, setup, tests |
| **Analyse de logs** | Parsing, enrichissement, corrélation d'événements |
| **Rédaction technique** | Documentation, schémas d'architecture |

---

## Auteur

**axo9cyber** — Etudiant en cybersécurité
Projet réalisé dans le cadre d'un lab de sécurité réseau personnalisé.

---

<p align="center">
  <i>Projet éducatif — Environnement de lab isolé</i>
</p>
