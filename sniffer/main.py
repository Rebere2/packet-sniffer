"""Point d'entrée du Packet Sniffer."""
import argparse
import sys
import time

from rich.live import Live

from sniffer.analyzer import Analyzer
from sniffer.capture import Capture
from sniffer.display import Display


def parse_args():
    """Analyse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(description="Packet Sniffer & Anomaly Detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface", help="Interface réseau à écouter (nécessite des privilèges)")
    group.add_argument("--demo", help="Fichier PCAP à rejouer")
    
    parser.add_argument("--filter", default="", help="Filtre BPF (ex: 'tcp or udp')")
    parser.add_argument("--output-dir", default=".", help="Dossier pour sauvegarder les rapports")
    
    return parser.parse_args()


def main():
    """Fonction principale."""
    args = parse_args()
    
    # Initialisation des composants
    analyzer = Analyzer()
    
    # TODO: Ajouter les détecteurs ici dans la Phase 2
    # analyzer.add_detector(ArpSpoofingDetector())
    # ...
    
    # Interface d'affichage
    display = Display(analyzer)
    
    # Capture réseau
    capture = Capture(
        analyzer=analyzer,
        interface=args.interface,
        pcap_file=args.demo,
        bpf_filter=args.filter
    )
    
    print("Démarrage du packet sniffer...")
    capture.start()
    
    # Boucle principale avec interface graphique
    try:
        with Live(display.render(), refresh_per_second=4) as live:
            while True:
                time.sleep(0.25)
                live.update(display.render())
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        print("\nArrêt du programme. Génération du rapport... (TODO)")
        # TODO: Appeler reporter.py pour générer HTML et PCAP


if __name__ == "__main__":
    main()
