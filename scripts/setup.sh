#!/usr/bin/env bash
# =============================================================================
# Script d'installation — Network Security Lab (Suricata + ELK)
# Auteur : axo9cyber
# Testé sur : Ubuntu 22.04 LTS
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Couleurs pour l'affichage
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${CYAN}══════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}══════════════════════════════════════${NC}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Variables de configuration
# ─────────────────────────────────────────────────────────────────────────────
SURICATA_INTERFACE="${SURICATA_IFACE:-eth0}"
SURICATA_LOG_DIR="/var/log/suricata"
SURICATA_CONFIG_DIR="/etc/suricata"
SURICATA_RULES_DIR="/etc/suricata/rules"
ELK_VERSION="8.12.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ─────────────────────────────────────────────────────────────────────────────
# Vérifications préalables
# ─────────────────────────────────────────────────────────────────────────────
check_prerequisites() {
    log_section "Vérification des prérequis"

    # Droits root
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root (sudo ./setup.sh)"
        exit 1
    fi
    log_ok "Droits root OK"

    # OS compatible
    if ! grep -q "Ubuntu\|Debian" /etc/os-release 2>/dev/null; then
        log_warn "OS non testé. Continuez à vos risques."
    else
        log_ok "OS compatible"
    fi

    # RAM disponible
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $TOTAL_RAM -lt 4096 ]]; then
        log_warn "RAM disponible : ${TOTAL_RAM}MB. Minimum recommandé : 8GB"
    else
        log_ok "RAM disponible : ${TOTAL_RAM}MB"
    fi

    # Interface réseau
    if ! ip link show "$SURICATA_INTERFACE" &>/dev/null; then
        log_error "Interface réseau '$SURICATA_INTERFACE' introuvable."
        log_info "Interfaces disponibles : $(ip link show | awk -F': ' '/^[0-9]+:/{print $2}' | tr '\n' ' ')"
        log_info "Relancez avec : SURICATA_IFACE=<interface> sudo ./setup.sh"
        exit 1
    fi
    log_ok "Interface réseau '$SURICATA_INTERFACE' trouvée"
}

# ─────────────────────────────────────────────────────────────────────────────
# Installation des dépendances
# ─────────────────────────────────────────────────────────────────────────────
install_dependencies() {
    log_section "Installation des dépendances système"

    apt-get update -qq
    apt-get install -y -qq \
        curl \
        wget \
        gnupg \
        apt-transport-https \
        ca-certificates \
        software-properties-common \
        jq \
        git \
        net-tools

    log_ok "Dépendances installées"
}

# ─────────────────────────────────────────────────────────────────────────────
# Installation de Docker
# ─────────────────────────────────────────────────────────────────────────────
install_docker() {
    log_section "Installation de Docker"

    if command -v docker &>/dev/null; then
        log_ok "Docker déjà installé ($(docker --version))"
        return 0
    fi

    curl -fsSL https://get.docker.com | bash
    systemctl enable docker
    systemctl start docker

    # Docker Compose v2
    apt-get install -y docker-compose-plugin

    log_ok "Docker installé"
}

# ─────────────────────────────────────────────────────────────────────────────
# Installation de Suricata
# ─────────────────────────────────────────────────────────────────────────────
install_suricata() {
    log_section "Installation de Suricata"

    if command -v suricata &>/dev/null; then
        log_ok "Suricata déjà installé ($(suricata --build-info | grep 'Version' | head -1))"
        return 0
    fi

    # Dépôt officiel OISF
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update -qq
    apt-get install -y suricata suricata-update

    log_ok "Suricata installé"
}

# ─────────────────────────────────────────────────────────────────────────────
# Configuration de Suricata
# ─────────────────────────────────────────────────────────────────────────────
configure_suricata() {
    log_section "Configuration de Suricata"

    # Sauvegarde de la config d'origine
    if [[ -f "$SURICATA_CONFIG_DIR/suricata.yaml" ]]; then
        cp "$SURICATA_CONFIG_DIR/suricata.yaml" "$SURICATA_CONFIG_DIR/suricata.yaml.bak.$(date +%s)"
        log_info "Config originale sauvegardée"
    fi

    # Copie de notre configuration
    cp "$PROJECT_DIR/configs/suricata/suricata.yaml" "$SURICATA_CONFIG_DIR/suricata.yaml"

    # Adapter l'interface réseau
    sed -i "s/interface: eth0/interface: $SURICATA_INTERFACE/g" "$SURICATA_CONFIG_DIR/suricata.yaml"

    # Copie des règles personnalisées
    mkdir -p "$SURICATA_RULES_DIR"
    cp "$PROJECT_DIR/configs/suricata/local.rules" "$SURICATA_RULES_DIR/local.rules"

    # Création du répertoire de logs
    mkdir -p "$SURICATA_LOG_DIR"
    chown -R suricata:suricata "$SURICATA_LOG_DIR" 2>/dev/null || true

    # Mise à jour des règles Emerging Threats
    log_info "Mise à jour des règles Suricata..."
    suricata-update update-sources
    suricata-update enable-source et/open
    suricata-update

    # Validation de la configuration
    log_info "Validation de la configuration Suricata..."
    if suricata -T -c "$SURICATA_CONFIG_DIR/suricata.yaml" -i "$SURICATA_INTERFACE" 2>&1 | grep -q "Configuration provided was successfully loaded"; then
        log_ok "Configuration Suricata valide"
    else
        log_warn "Vérifiez la configuration manuellement : suricata -T -c $SURICATA_CONFIG_DIR/suricata.yaml"
    fi

    log_ok "Suricata configuré"
}

# ─────────────────────────────────────────────────────────────────────────────
# Configuration du service Suricata
# ─────────────────────────────────────────────────────────────────────────────
setup_suricata_service() {
    log_section "Configuration du service Suricata"

    # Configuration du service systemd
    cat > /etc/default/suricata << EOF
# Configuration de démarrage Suricata
IFACE="$SURICATA_INTERFACE"
LISTENMODE=af-packet
EOF

    systemctl daemon-reload
    systemctl enable suricata
    systemctl start suricata

    sleep 3

    if systemctl is-active --quiet suricata; then
        log_ok "Service Suricata démarré"
    else
        log_warn "Suricata n'a pas démarré. Vérifiez : journalctl -u suricata"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Démarrage de la pile ELK
# ─────────────────────────────────────────────────────────────────────────────
start_elk_stack() {
    log_section "Démarrage de la pile ELK (Docker)"

    cd "$PROJECT_DIR"

    # Ajustement vm.max_map_count pour Elasticsearch
    sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf

    log_info "Démarrage des conteneurs ELK..."
    docker compose up -d elasticsearch kibana logstash

    log_info "Attente de la disponibilité d'Elasticsearch..."
    local max_retries=30
    local count=0
    while ! curl -s http://localhost:9200/_cluster/health &>/dev/null; do
        count=$((count + 1))
        if [[ $count -ge $max_retries ]]; then
            log_error "Elasticsearch ne répond pas après ${max_retries} tentatives"
            log_info "Vérifiez les logs : docker compose logs elasticsearch"
            break
        fi
        echo -n "."
        sleep 5
    done
    echo ""

    log_ok "Pile ELK démarrée"
    log_info "Elasticsearch : http://localhost:9200"
    log_info "Kibana        : http://localhost:5601"
}

# ─────────────────────────────────────────────────────────────────────────────
# Application du template Elasticsearch
# ─────────────────────────────────────────────────────────────────────────────
apply_elasticsearch_template() {
    log_section "Application du template Elasticsearch"

    sleep 10  # Attente que ES soit complètement prêt

    if curl -s -X PUT "http://localhost:9200/_index_template/suricata" \
        -H "Content-Type: application/json" \
        -d @"$PROJECT_DIR/configs/elasticsearch/index-template.json" | grep -q '"acknowledged":true'; then
        log_ok "Template Elasticsearch appliqué"
    else
        log_warn "Échec de l'application du template. Réessayez manuellement."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Résumé de l'installation
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    log_section "Installation terminée"

    echo ""
    echo -e "${GREEN}Services déployés :${NC}"
    echo -e "  • Suricata IDS     → en écoute sur $SURICATA_INTERFACE"
    echo -e "  • Elasticsearch    → http://localhost:9200"
    echo -e "  • Kibana           → http://localhost:5601"
    echo -e "  • Logstash         → port 5044 (Beats)"
    echo ""
    echo -e "${YELLOW}Prochaines étapes :${NC}"
    echo -e "  1. Ouvrir Kibana : http://localhost:5601"
    echo -e "  2. Créer le Data View : suricata-*"
    echo -e "  3. Importer les dashboards (Kibana → Stack Management → Saved Objects)"
    echo -e "  4. Lancer les tests de détection : ./scripts/test-detection.sh"
    echo ""
    echo -e "${BLUE}Logs Suricata :${NC} $SURICATA_LOG_DIR/eve.json"
    echo -e "${BLUE}Logs ELK :${NC} docker compose logs -f"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée principal
# ─────────────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${CYAN}  ╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║   Network Security Lab — Suricata + ELK  ║${NC}"
    echo -e "${CYAN}  ║   Script d'installation automatisé       ║${NC}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════╝${NC}"
    echo ""

    check_prerequisites
    install_dependencies
    install_docker
    install_suricata
    configure_suricata
    setup_suricata_service
    start_elk_stack
    apply_elasticsearch_template
    print_summary
}

main "$@"
