#!/usr/bin/env bash
# =============================================================================
# Script de tests de détection — Network Security Lab
# Auteur : axo9cyber
# Description : Simule des scénarios d'attaque pour valider les règles Suricata
# AVERTISSEMENT : À utiliser UNIQUEMENT dans un environnement de lab isolé
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Couleurs
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()    { echo -e "${YELLOW}[TEST]${NC}  $1"; }
log_section() { echo -e "\n${CYAN}── $1 ──${NC}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
TARGET_IP="${TARGET_IP:-192.168.100.30}"
TARGET_PORT="${TARGET_PORT:-80}"
SURICATA_LOG="/var/log/suricata/eve.json"
WAIT_SECONDS=3

# ─────────────────────────────────────────────────────────────────────────────
# Vérifications
# ─────────────────────────────────────────────────────────────────────────────
check_tools() {
    local missing=()
    for tool in curl nmap nc ping; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Outils manquants : ${missing[*]}"
        log_info "Installation : apt-get install -y nmap netcat-openbsd curl"
    fi
}

# Compter les alertes Suricata générées
count_alerts() {
    local keyword="$1"
    if [[ -f "$SURICATA_LOG" ]]; then
        grep -c "$keyword" "$SURICATA_LOG" 2>/dev/null || echo "0"
    else
        echo "0 (log introuvable)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — Scan de ports SYN (Nmap)
# ─────────────────────────────────────────────────────────────────────────────
test_port_scan() {
    log_section "TEST 1 : Scan de ports SYN (Nmap)"
    log_warn "Cible : $TARGET_IP — Scan SYN sur ports communs"

    if ! command -v nmap &>/dev/null; then
        log_info "Nmap non disponible. Simulation avec curl multi-ports..."
        for port in 22 80 443 8080 3306 5432; do
            curl -s --connect-timeout 1 "http://$TARGET_IP:$port" &>/dev/null || true
        done
    else
        nmap -sS --top-ports 100 -T4 "$TARGET_IP" -oN /tmp/nmap_test.txt 2>/dev/null || true
    fi

    sleep "$WAIT_SECONDS"
    ALERTS=$(count_alerts "SCAN")
    log_ok "Test terminé — Alertes SCAN détectées : $ALERTS"
}

# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — Connexions SSH rapides (simulation brute-force)
# ─────────────────────────────────────────────────────────────────────────────
test_ssh_bruteforce() {
    log_section "TEST 2 : Simulation de force brute SSH"
    log_warn "Cible : $TARGET_IP:22 — Connexions SSH répétées"

    for i in $(seq 1 8); do
        # Tentative de connexion SSH (échoue intentionnellement)
        timeout 2 nc -z "$TARGET_IP" 22 &>/dev/null || true
        sleep 0.5
    done

    sleep "$WAIT_SECONDS"
    ALERTS=$(count_alerts "BRUTEFORCE\|brute")
    log_ok "Test terminé — Alertes Brute Force détectées : $ALERTS"
}

# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Requêtes HTTP suspectes (simulation scan web)
# ─────────────────────────────────────────────────────────────────────────────
test_web_scan() {
    log_section "TEST 3 : Simulation de scan de vulnérabilités web"
    log_warn "Cible : http://$TARGET_IP:$TARGET_PORT — Requêtes HTTP suspectes"

    # Simulation de Nikto (User-Agent)
    curl -s -A "Mozilla/5.00 (Nikto/2.1.6)" \
        "http://$TARGET_IP:$TARGET_PORT/" &>/dev/null || true

    # Tentative de traversée de répertoire
    curl -s "http://$TARGET_IP:$TARGET_PORT/../../../../etc/passwd" &>/dev/null || true

    # Tentative SQL injection basique
    curl -s "http://$TARGET_IP:$TARGET_PORT/?id=1'+OR+'1'='1" &>/dev/null || true

    # Tentative XSS basique
    curl -s "http://$TARGET_IP:$TARGET_PORT/?q=<script>alert(1)</script>" &>/dev/null || true

    sleep "$WAIT_SECONDS"
    ALERTS=$(count_alerts "WEBAPP\|SCAN\|web")
    log_ok "Test terminé — Alertes Web détectées : $ALERTS"
}

# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Ping sweep ICMP
# ─────────────────────────────────────────────────────────────────────────────
test_icmp_sweep() {
    log_section "TEST 4 : ICMP Ping Sweep"
    log_warn "Cible : réseau 192.168.100.0/24 — Scan ICMP"

    for host in $(seq 1 20); do
        ping -c 1 -W 1 "192.168.100.$host" &>/dev/null || true
    done

    sleep "$WAIT_SECONDS"
    ALERTS=$(count_alerts "ICMP\|icmp")
    log_ok "Test terminé — Alertes ICMP détectées : $ALERTS"
}

# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — Vérification Elasticsearch reçoit les alertes
# ─────────────────────────────────────────────────────────────────────────────
test_elasticsearch_ingestion() {
    log_section "TEST 5 : Vérification de l'ingestion Elasticsearch"

    if ! curl -s "http://localhost:9200" &>/dev/null; then
        log_warn "Elasticsearch non accessible sur localhost:9200"
        return 0
    fi

    # Attendre l'ingestion
    sleep 10

    # Compter les documents dans les index Suricata
    TOTAL=$(curl -s "http://localhost:9200/suricata-*/_count" 2>/dev/null | jq -r '.count' 2>/dev/null || echo "N/A")
    ALERT_COUNT=$(curl -s "http://localhost:9200/suricata-alert-*/_count" 2>/dev/null | jq -r '.count' 2>/dev/null || echo "N/A")

    log_ok "Documents dans Elasticsearch :"
    log_info "  Total (tous types) : $TOTAL"
    log_info "  Alertes uniquement : $ALERT_COUNT"
}

# ─────────────────────────────────────────────────────────────────────────────
# Rapport final
# ─────────────────────────────────────────────────────────────────────────────
print_report() {
    log_section "RAPPORT DE TESTS"

    echo ""
    echo -e "${GREEN}Tests exécutés :${NC}"
    echo -e "  [1] Scan de ports SYN (Nmap)"
    echo -e "  [2] Force brute SSH"
    echo -e "  [3] Scan de vulnérabilités web"
    echo -e "  [4] ICMP Ping Sweep"
    echo -e "  [5] Vérification ingestion ELK"
    echo ""

    if [[ -f "$SURICATA_LOG" ]]; then
        TOTAL_ALERTS=$(grep -c '"event_type":"alert"' "$SURICATA_LOG" 2>/dev/null || echo "0")
        echo -e "${CYAN}Total alertes dans eve.json : $TOTAL_ALERTS${NC}"
    fi

    echo ""
    echo -e "${YELLOW}Consultez les résultats dans Kibana : http://localhost:5601${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${RED}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}  ║  AVERTISSEMENT : USAGE LAB ISOLÉ UNIQUEMENT     ║${NC}"
    echo -e "${RED}  ║  Ne jamais utiliser sur un réseau de production  ║${NC}"
    echo -e "${RED}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Cible  : ${TARGET_IP}"
    echo -e "  Logs   : ${SURICATA_LOG}"
    echo ""

    read -r -p "Confirmer les tests sur $TARGET_IP ? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Tests annulés."
        exit 0
    fi

    check_tools
    test_port_scan
    test_ssh_bruteforce
    test_web_scan
    test_icmp_sweep
    test_elasticsearch_ingestion
    print_report
}

main "$@"
