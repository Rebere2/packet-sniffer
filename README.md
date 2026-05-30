# Packet Sniffer & Anomaly Detector

Un outil d'analyse réseau en temps réel conçu pour les équipes de sécurité (SOC / Blue Team). Il capture le trafic, l'analyse à la recherche de comportements malveillants et fournit une interface terminal claire ainsi qu'un rapport détaillé.

## Fonctionnalités

- **Capture en Temps Réel** : Analyse du trafic réseau via une interface spécifique.
- **Interface Terminal** : Suivi en direct du trafic, des alertes et des statistiques.
- **Détection d'Anomalies** :
  - *ARP Spoofing* : Détecte si deux adresses MAC revendiquent la même adresse IP.
  - *Port Scan (SYN)* : Repère les balayages massifs de ports depuis une même source.
  - *ICMP Flood* : Identifie les attaques par déni de service basées sur le protocole ICMP.
  - *DNS Anomaly* : Surveille les requêtes DNS suspectes et les floods.
  - *Threat Intel* : Vérification des IP source/destination contre des listes noires.
- **Mode Démo** : Rejouez des fichiers PCAP pour analyser du trafic hors-ligne.
- **Génération de Rapports** : À la fin de la capture, un rapport complet et professionnel est généré (HTML).

## Prérequis

- Python 3.11+
- `scapy`, `rich`, `jinja2`, `pytest` (voir `requirements.txt`)
- **Note importante** : La capture en temps réel nécessite les droits administrateur (root).

## Installation

```bash
git clone https://github.com/Rebere2/packet-sniffer.git
cd packet-sniffer
pip install -r requirements.txt
```

## Utilisation

### Mode Démo (Sans privilèges)
Permet d'analyser un fichier PCAP existant. Idéal pour tester l'outil.
```bash
python -m sniffer.main --demo data/samples/port_scan.pcap
```

### Mode Temps Réel (Nécessite root)
```bash
sudo python -m sniffer.main --interface eth0
```

Vous pouvez également filtrer le trafic capturé (syntaxe BPF) :
```bash
sudo python -m sniffer.main --interface eth0 --filter "tcp or udp"
```

## Limitations

- Le trafic chiffré (HTTPS, SSH) ne permet pas d'analyser le contenu (payload), seules les métadonnées sont vérifiées.
- Les seuils de détection peuvent générer des faux positifs sur les réseaux très denses.
- L'analyse en temps réel consomme des ressources CPU sur les interfaces à fort débit (10Gbps+).

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.
