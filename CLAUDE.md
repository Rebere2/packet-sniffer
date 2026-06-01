# CLAUDE.md — Packet Sniffer + Anomaly Detector

## Vue d'ensemble du projet

Outil de capture réseau en temps réel qui analyse le trafic sur une interface
et détecte automatiquement des comportements suspects : ARP spoofing, port scans,
flood DNS, trafic vers des IPs malveillantes connues, etc.

Résultat visible : terminal interactif en temps réel + export PCAP annoté + rapport HTML.
Projet portfolio cybersécurité — orienté SOC / Blue Team.

---

## Stack technique

- **Langage** : Python 3.11+
- **Capture réseau** : Scapy
- **Affichage terminal** : Rich (tableaux, progress bars, live update)
- **Export rapport** : Jinja2 (HTML) + dpkt ou scapy pour PCAP annoté
- **Tests** : pytest + fichiers PCAP de test (pas besoin de vrai réseau)
- **Packaging** : Docker avec `--net=host` pour l'accès réseau

> Note : nécessite les droits root/sudo pour capturer les paquets.
> Prévoir un mode `--demo` qui rejoue un fichier PCAP existant sans root.

---

## Structure du projet attendue

```
packet-sniffer/
├── CLAUDE.md
├── README.md
├── LICENSE                 ← MIT
├── .gitignore
├── requirements.txt
├── Dockerfile
│
├── sniffer/
│   ├── __init__.py
│   ├── main.py             ← point d'entrée CLI (argparse)
│   ├── capture.py          ← capture Scapy, gestion interface réseau
│   ├── analyzer.py         ← dispatch des paquets vers les détecteurs
│   ├── display.py          ← affichage Rich en temps réel
│   └── reporter.py         ← génération rapport HTML + export PCAP annoté
│
├── detectors/
│   ├── __init__.py
│   ├── base.py             ← classe abstraite BaseDetector
│   ├── arp_spoofing.py     ← détection ARP spoofing / poisoning
│   ├── port_scan.py        ← détection SYN scan, NULL scan, XMAS scan
│   ├── dns_anomaly.py      ← flood DNS, requêtes vers domaines suspects
│   ├── icmp_flood.py       ← détection ICMP flood / ping of death
│   └── threat_intel.py     ← vérification IPs contre listes noires publiques
│
├── data/
│   ├── blacklists/
│   │   ├── malicious_ips.txt      ← IPs malveillantes (Feodo Tracker, etc.)
│   │   └── malicious_domains.txt  ← domaines suspects
│   └── samples/
│       ├── arp_spoof.pcap         ← PCAP de test ARP spoofing
│       ├── port_scan.pcap         ← PCAP de test nmap SYN scan
│       └── normal_traffic.pcap    ← trafic légitime pour baseline
│
├── templates/
│   └── report.html.j2      ← template Jinja2 pour le rapport HTML
│
└── tests/
    ├── test_arp_detector.py
    ├── test_port_scan_detector.py
    ├── test_dns_detector.py
    └── test_reporter.py
```

---

## Fonctionnalités à implémenter (par ordre de priorité)

### Phase 1 — Capture et affichage (MVP)
- [ ] Lister les interfaces réseau disponibles au démarrage
- [ ] Capturer les paquets en temps réel avec Scapy (`sniff()`)
- [ ] Afficher en live avec Rich :
  - tableau des derniers paquets (src IP, dst IP, protocole, taille, timestamp)
  - compteurs par protocole (TCP, UDP, ICMP, ARP, DNS)
  - alertes en rouge quand une anomalie est détectée
- [ ] Mode `--demo <fichier.pcap>` pour rejouer un PCAP sans root

### Phase 2 — Détecteurs d'anomalies
- [ ] **ARP Spoofing** : détecter si deux MACs différentes revendiquent la même IP
- [ ] **Port Scan** : détecter un nombre anormal de SYN vers des ports différents
  depuis la même IP source dans une fenêtre de temps (ex: >20 ports en 5s)
- [ ] **DNS Anomaly** : détecter flood (>50 requêtes/s) et réponses avec TTL=0
- [ ] **ICMP Flood** : détecter >100 pings/s vers la même cible
- [ ] **Threat Intel** : vérifier chaque IP contre `data/blacklists/malicious_ips.txt`

Chaque détecteur hérite de `BaseDetector` et implémente :
```python
def analyze(self, packet) -> Alert | None
```

### Phase 3 — Alertes et rapport
- [ ] Système d'alertes avec 3 niveaux : INFO, WARNING, CRITICAL
- [ ] Affichage des alertes en temps réel dans un panneau Rich dédié
- [ ] À la fin de la session (Ctrl+C), générer :
  - `report_YYYYMMDD_HHMMSS.html` avec résumé des alertes, stats, timeline
  - `capture_YYYYMMDD_HHMMSS.pcap` annoté (paquets suspects marqués)
- [ ] Option `--output-dir` pour choisir où sauvegarder les fichiers

### Phase 4 — Fonctionnalités avancées
- [ ] Mise à jour automatique des blacklists au démarrage (Feodo Tracker API)
- [ ] Option `--filter` pour capturer uniquement certains protocoles
- [ ] Baseline automatique : apprend le trafic "normal" pendant 60s avant de détecter
- [ ] Webhooks : envoyer les alertes CRITICAL vers une URL configurable (Slack, Discord)

---

## Architecture des détecteurs

Chaque détecteur est indépendant et stateful (il maintient son propre état entre les paquets) :

```python
# detectors/base.py
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class Alert:
    severity: Severity
    detector: str
    message: str
    src_ip: str
    dst_ip: str | None
    timestamp: float
    packet_summary: str

class BaseDetector:
    name: str = "base"

    def analyze(self, packet) -> Alert | None:
        raise NotImplementedError

    def reset(self) -> None:
        """Remet à zéro l'état interne du détecteur."""
        pass
```

---

## Conventions de code

- **Style** : PEP8 strict, type hints partout, docstrings sur chaque classe et méthode publique
- **Logs** : `logging` standard, pas de `print()` sauf dans `display.py`
- **Sécurité** : ne jamais logger le contenu des paquets (payload) — uniquement les métadonnées
- **Commits** : messages en anglais, format `feat:`, `fix:`, `docs:`, `test:`
- **Tests** : utiliser les fichiers PCAP dans `data/samples/` — aucun test ne doit
  nécessiter un vrai accès réseau

---

## Exigences de qualité portfolio

- README.md doit inclure :
  - GIF de démonstration du terminal Rich en action (obligatoire — c'est le wow factor)
  - screenshot du rapport HTML généré
  - section "Détecteurs disponibles" avec explication de chaque menace détectée
  - section "Limitations" : faux positifs possibles, trafic chiffré non analysable, etc.
  - instructions claires pour lancer en mode `--demo` sans root
  - badge "Python 3.11+" et badge "License MIT"
- Le mode `--demo` doit fonctionner sans sudo sur n'importe quelle machine
  (c'est ce que le recruteur va tester)
- Les fichiers PCAP de test dans `data/samples/` doivent être inclus dans le repo
  (taille raisonnable, <5MB chacun)

---

## Commandes utiles

```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer sur l'interface réseau eth0 (nécessite sudo)
sudo python -m sniffer.main --interface eth0

# Mode démo sans sudo (rejoue un PCAP)
python -m sniffer.main --demo data/samples/port_scan.pcap

# Lancer avec filtre protocole
sudo python -m sniffer.main --interface eth0 --filter "tcp or udp"

# Lancer les tests
pytest tests/ -v

# Build Docker (accès réseau hôte)
docker build -t packet-sniffer .
docker run --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN packet-sniffer
```

---

## Sources pour les blacklists et PCAP de test

- Feodo Tracker (IPs C2 botnet) : https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- PCAP samples légitimes : https://www.wireshark.org/docs/wsug_html_chunked/AppBFiles.html
- PCAP d'attaques pour tests : https://www.malware-traffic-analysis.net (usage éducatif)
- SecRepo (dataset réseau) : https://www.secrepo.com
