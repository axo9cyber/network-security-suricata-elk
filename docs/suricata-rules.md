# Documentation des règles Suricata

## Structure d'une règle Suricata

```
action proto src_ip src_port direction dst_ip dst_port (options)
```

| Champ       | Description                                 | Exemple           |
|-------------|---------------------------------------------|-------------------|
| `action`    | Action à effectuer (alert/drop/pass/reject)  | `alert`           |
| `proto`     | Protocole réseau                             | `tcp`, `udp`, `icmp`, `http` |
| `src_ip`    | IP source                                    | `$EXTERNAL_NET`   |
| `src_port`  | Port source                                  | `any`             |
| `direction` | Sens du trafic                               | `->`, `<-`, `<>`  |
| `dst_ip`    | IP destination                               | `$HOME_NET`       |
| `dst_port`  | Port destination                             | `$HTTP_PORTS`     |

### Options clés

| Option         | Description                                      |
|----------------|--------------------------------------------------|
| `msg`          | Message de l'alerte                              |
| `content`      | Contenu textuel à rechercher                     |
| `pcre`         | Expression régulière Perl                        |
| `flow`         | Direction du flux (to_server, established...)    |
| `flags`        | Flags TCP (S=SYN, A=ACK, F=FIN...)               |
| `threshold`    | Limite de déclenchement (seuil / fenêtre)        |
| `classtype`    | Classification de l'alerte                       |
| `sid`          | Identifiant unique de la règle                   |
| `rev`          | Révision de la règle                             |
| `nocase`       | Recherche insensible à la casse                  |

---

## Règles personnalisées du lab

### Numérotation des SIDs

| Plage SID       | Catégorie                        |
|-----------------|----------------------------------|
| 9000001–9000999 | Scans de reconnaissance          |
| 9001001–9001999 | Attaques par force brute         |
| 9002001–9002999 | Attaques d'applications web      |
| 9003001–9003999 | Activité ICMP suspecte           |
| 9004001–9004999 | Exfiltration de données / C2     |
| 9005001–9005999 | Détection d'outils offensifs     |

---

### Catégorie 1 : Scans de reconnaissance

#### SID 9000001 — SYN Scan

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"LAB-SCAN Possible SYN Scan Detected";
    flags:S,12;
    threshold: type both, track by_src, count 20, seconds 2;
    classtype:attempted-recon;
    sid:9000001; rev:1;
)
```

**Logique** : Détecte un envoi massif de paquets SYN (flag S uniquement) depuis une même source. Un scanner de ports comme Nmap en mode `-sS` envoie des centaines de SYN/seconde.

**Seuil** : 20 paquets SYN en 2 secondes depuis la même IP source.

---

#### SID 9000003 — Nmap User-Agent HTTP

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LAB-SCAN Nmap HTTP User-Agent Detected";
    content:"Nmap Scripting Engine";
    http_user_agent;
    classtype:attempted-recon;
    sid:9000003; rev:1;
)
```

**Logique** : Nmap avec les scripts NSE (`-sC` ou `--script`) envoie des requêtes HTTP avec un User-Agent caractéristique. La règle cherche la chaîne "Nmap Scripting Engine" dans l'en-tête HTTP User-Agent.

---

### Catégorie 2 : Force brute

#### SID 9001001 — Force brute SSH

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $SSH_PORTS (
    msg:"LAB-BRUTEFORCE SSH Brute Force Attempt";
    flow:to_server,established;
    content:"SSH-";
    threshold: type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:9001001; rev:1;
)
```

**Logique** : Une attaque brute-force SSH génère de nombreuses connexions TCP établies vers le port 22. La présence du banner SSH ("SSH-") indique une connexion complète. 5 connexions en 1 minute depuis la même IP est suspect.

---

### Catégorie 3 : Attaques web

#### SID 9002002 — Traversée de répertoire

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LAB-WEBAPP Directory Traversal Attempt";
    flow:to_server,established;
    content:"../";
    http_uri;
    pcre:"/(\.\./){3,}/U";
    classtype:web-application-attack;
    sid:9002002; rev:1;
)
```

**Logique** : Une attaque de traversée de répertoire utilise des séquences `../` dans l'URL pour sortir de la racine web. La règle cherche d'abord `../` dans l'URI puis vérifie avec une regex que la séquence apparaît au moins 3 fois consécutives.

---

#### SID 9002003 — SQL Injection

```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LAB-WEBAPP SQL Injection Attempt";
    flow:to_server,established;
    pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i";
    http_uri;
    classtype:web-application-attack;
    sid:9002003; rev:1;
)
```

**Logique** : Les injections SQL utilisent des caractères spéciaux : guillemet simple `'` (encodé `%27`), double tiret `--` (commentaire SQL), dièse `#` (commentaire MySQL). La regex détecte ces patterns dans l'URI.

---

### Catégorie 4 : Exfiltration / C2

#### SID 9004003 — DNS Tunneling

```
alert dns $HOME_NET any -> any 53 (
    msg:"LAB-EXFIL Abnormally Long DNS Query Possible Tunneling";
    dns.query;
    pcre:"/^.{50,}\./";
    classtype:policy-violation;
    sid:9004003; rev:1;
)
```

**Logique** : Le DNS tunneling encode des données dans les requêtes DNS (sous-domaines très longs). Un nom de domaine légitime dépasse rarement 30-40 caractères. La regex détecte les requêtes DNS avec plus de 50 caractères avant le premier point.

---

## Variables d'environnement Suricata

Définies dans `suricata.yaml` :

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24]"     # Réseau interne du lab
    EXTERNAL_NET: "!$HOME_NET"          # Tout ce qui n'est pas HOME_NET
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    SSH_PORTS: 22
    HTTP_PORTS: "80"
```

---

## Niveaux de sévérité Suricata

| Sévérité | Label  | Description                                       |
|----------|--------|---------------------------------------------------|
| 1        | High   | Menace sérieuse, compromission probable           |
| 2        | Medium | Activité suspecte, investigation recommandée      |
| 3        | Low    | Information, reconnaissance, activité anormale   |

---

## Classifications des alertes (classtype)

| Classtype                  | Description                          |
|----------------------------|--------------------------------------|
| `attempted-recon`          | Tentative de reconnaissance           |
| `attempted-admin`          | Tentative d'accès admin              |
| `attempted-user`           | Tentative d'accès utilisateur        |
| `web-application-attack`   | Attaque d'application web            |
| `trojan-activity`          | Activité de cheval de Troie          |
| `shellcode-detect`         | Shellcode détecté                    |
| `attempted-dos`            | Tentative de déni de service         |
| `policy-violation`         | Violation de politique               |

---

## Tester une règle spécifique

```bash
# Activer le mode debug pour une SID spécifique
sudo suricata -c /etc/suricata/suricata.yaml -i enp0s3 \
    --set logging.outputs.1.console.enabled=yes \
    -S /etc/suricata/rules/local.rules

# Lister toutes les règles chargées
sudo suricata --list-runmodes

# Tester la syntaxe d'un fichier de règles
sudo suricata -T -c /etc/suricata/suricata.yaml \
    -S /etc/suricata/rules/local.rules
```

---

## Ressources pour les règles

- [Emerging Threats Open Rules](https://rules.emergingthreats.net/)
- [Suricata Rules Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Rule Management avec suricata-update](https://suricata-update.readthedocs.io/)
