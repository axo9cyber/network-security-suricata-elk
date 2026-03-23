# Guide d'installation détaillé

## Prérequis

### Matériel recommandé

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| RAM       | 6 GB    | 12 GB      |
| CPU       | 4 vCPU  | 8 vCPU     |
| Disque    | 50 GB   | 100 GB SSD |

### Logiciels requis

- VirtualBox 7.x (ou VMware)
- Ubuntu 22.04 LTS pour la VM IDS/ELK
- Kali Linux 2024.x pour la VM attaquant
- Docker 24.x + Docker Compose v2

---

## Architecture des VMs VirtualBox

### Création des machines virtuelles

#### VM-1 — Attaquant (Kali Linux)

```
Nom          : Kali-Attaquant
OS           : Debian (64-bit)
RAM          : 2048 MB
Disque       : 40 GB
Réseau       : Adaptateur 1 → Réseau interne (lab-net)
              Adaptateur 2 → NAT (accès internet)
```

#### VM-2 — IDS + ELK (Ubuntu 22.04)

```
Nom          : IDS-ELK
OS           : Ubuntu (64-bit)
RAM          : 6144 MB (minimum)
Disque       : 80 GB
Réseau       : Adaptateur 1 → Réseau interne (lab-net) [mode promiscuité : Tout]
              Adaptateur 2 → NAT (accès internet)
```

> **Important** : L'adaptateur en mode promiscuité permet à Suricata de capturer tout le trafic du réseau interne, y compris celui à destination d'autres VMs.

#### VM-3 — Cible (Ubuntu 22.04)

```
Nom          : Serveur-Cible
OS           : Ubuntu (64-bit)
RAM          : 1024 MB
Disque       : 20 GB
Réseau       : Adaptateur 1 → Réseau interne (lab-net)
```

### Configuration du réseau interne VirtualBox

Créer un réseau interne nommé `lab-net` :

```
VirtualBox → Fichier → Gestionnaire de réseau hôte → Nouveau réseau interne
Nom    : lab-net
Plage  : 192.168.100.0/24
```

Attribuer les IPs statiques sur chaque VM :

```bash
# Sur chaque VM — éditer /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    enp0s3:  # Remplacer par le nom de l'interface
      dhcp4: false
      addresses:
        - 192.168.100.X/24  # 10=Kali, 20=IDS, 30=Cible
      gateway4: 192.168.100.1
```

```bash
sudo netplan apply
```

---

## Installation de Suricata (VM-2)

### 1. Installation via PPA officiel

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata suricata-update
```

### 2. Vérification de l'installation

```bash
suricata --build-info | grep Version
# Suricata version 7.x.x RELEASE
```

### 3. Mise à jour des règles

```bash
# Activer la source Emerging Threats Open (gratuite)
sudo suricata-update enable-source et/open

# Mettre à jour toutes les règles actives
sudo suricata-update

# Lister les sources disponibles
suricata-update list-sources
```

### 4. Déploiement de la configuration

```bash
# Cloner le projet
git clone https://github.com/axo9cyber/network-security-suricata-elk.git
cd network-security-suricata-elk

# Copier les configurations
sudo cp configs/suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo cp configs/suricata/local.rules /etc/suricata/rules/local.rules

# Adapter l'interface réseau (enp0s3, eth0, etc.)
sudo sed -i 's/interface: eth0/interface: enp0s3/g' /etc/suricata/suricata.yaml
```

### 5. Test de la configuration

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -i enp0s3
# Résultat attendu : "Configuration provided was successfully loaded."
```

### 6. Démarrage du service

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

### 7. Vérification de la génération des logs

```bash
# Surveiller les alertes en temps réel
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

## Déploiement de la pile ELK (VM-2)

### 1. Prérequis Docker

```bash
# Installation de Docker
curl -fsSL https://get.docker.com | sudo bash
sudo systemctl enable docker
sudo systemctl start docker

# Ajout de l'utilisateur au groupe docker
sudo usermod -aG docker $USER
newgrp docker

# Vérification
docker --version
docker compose version
```

### 2. Configuration vm.max_map_count (requis par Elasticsearch)

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 3. Démarrage de la pile ELK

```bash
cd network-security-suricata-elk

# Démarrer Elasticsearch, Logstash et Kibana
docker compose up -d elasticsearch logstash kibana

# Surveiller les logs
docker compose logs -f

# Vérifier l'état des conteneurs
docker compose ps
```

### 4. Vérification d'Elasticsearch

```bash
# Santé du cluster
curl http://localhost:9200/_cluster/health?pretty

# Résultat attendu :
# {
#   "cluster_name" : "suricata-lab",
#   "status" : "green",
#   ...
# }
```

### 5. Application du template d'index

```bash
curl -X PUT "http://localhost:9200/_index_template/suricata" \
     -H "Content-Type: application/json" \
     -d @configs/elasticsearch/index-template.json
```

### 6. Accès à Kibana

Ouvrir `http://localhost:5601` dans un navigateur.

**Création du Data View :**

1. Menu → Stack Management → Data Views
2. Cliquer "Create data view"
3. Index pattern : `suricata-*`
4. Timestamp field : `@timestamp`
5. Sauvegarder

---

## Configuration de Kibana — Dashboards

### Création du dashboard "Network Security Overview"

#### 1. Timeline des alertes

- Visualisation : Bar chart (stacked)
- Index : `suricata-alert-*`
- Axe X : `@timestamp` (Date histogram, intervalle auto)
- Axe Y : Count

#### 2. Top 10 IPs sources

- Visualisation : Data table
- Index : `suricata-alert-*`
- Agrégation : Terms sur `source.ip`
- Taille : 10

#### 3. Répartition par catégorie

- Visualisation : Pie chart
- Index : `suricata-alert-*`
- Agrégation : Terms sur `alert.category`

#### 4. Carte GeoIP

- Visualisation : Maps
- Couche : Documents
- Index : `suricata-alert-*`
- Champ : `source.geo.location`

---

## Dépannage

### Suricata ne démarre pas

```bash
# Vérifier les logs
journalctl -u suricata -n 50

# Tester la configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### Elasticsearch en rouge

```bash
# Vérifier les logs du conteneur
docker logs elasticsearch --tail 50

# Problème vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
docker restart elasticsearch
```

### Aucune alerte dans Kibana

```bash
# Vérifier que Suricata génère des logs
ls -la /var/log/suricata/eve.json
sudo tail -20 /var/log/suricata/eve.json

# Vérifier le pipeline Logstash
docker logs logstash --tail 30

# Vérifier les index dans Elasticsearch
curl http://localhost:9200/_cat/indices?v
```

### Logstash ne lit pas les logs

```bash
# Vérifier les permissions
sudo ls -la /var/log/suricata/
sudo chmod 644 /var/log/suricata/eve.json

# Vérifier le montage du volume Docker
docker inspect logstash | jq '.[0].Mounts'
```
