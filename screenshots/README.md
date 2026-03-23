# Captures d'écran du projet

Ce répertoire contient les captures d'écran documentant le projet.

## À ajouter

| Fichier                          | Description                                     |
|----------------------------------|-------------------------------------------------|
| `01-architecture-lab.png`        | Schéma VirtualBox avec les 3 VMs               |
| `02-suricata-running.png`        | Service Suricata actif + logs eve.json en temps réel |
| `03-nmap-scan.png`               | Scan Nmap depuis Kali Linux                    |
| `04-suricata-alert-nmap.png`     | Alerte Suricata déclenchée par le scan Nmap    |
| `05-elk-stack-docker.png`        | Conteneurs ELK en cours d'exécution            |
| `06-elasticsearch-indices.png`   | Index suricata-* dans Elasticsearch            |
| `07-kibana-discover.png`         | Exploration des logs dans Kibana Discover      |
| `08-kibana-dashboard-overview.png` | Dashboard principal "Network Security Overview" |
| `09-kibana-alert-timeline.png`   | Timeline des alertes IDS                       |
| `10-kibana-top-ips.png`          | Top IPs sources malveillantes                  |
| `11-kibana-geoip-map.png`        | Carte GeoIP des sources d'attaque              |
| `12-kibana-attack-categories.png`| Répartition par catégorie d'attaque            |
| `13-ssh-bruteforce-detection.png`| Détection d'une attaque force brute SSH        |
| `14-web-scan-detection.png`      | Détection d'un scan de vulnérabilités web      |

## Comment prendre les captures

```bash
# Depuis la VM IDS, afficher les alertes en temps réel
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {time:.timestamp, sig:.alert.signature, src:.src_ip, dst:.dest_ip}'
```

Les captures peuvent être ajoutées via :
```
git add screenshots/
git commit -m "docs: add screenshots of lab environment"
```
