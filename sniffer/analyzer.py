"""Module d'analyse des paquets."""
import time
from collections import defaultdict
from typing import List, Dict, Any, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert


class Analyzer:
    """Gestionnaire central de l'analyse réseau.
    
    Responsable de la distribution des paquets aux différents détecteurs
    et du suivi des statistiques globales.
    """
    
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        """Initialise l'analyseur avec une liste de détecteurs."""
        self.detectors: List[BaseDetector] = detectors or []
        
        # Statistiques
        self.start_time: float = time.time()
        self.total_packets: int = 0
        self.protocols: Dict[str, int] = defaultdict(int)
        self.recent_packets: List[Dict[str, Any]] = []
        
        # Alertes
        self.alerts: List[Alert] = []
        
    def add_detector(self, detector: BaseDetector) -> None:
        """Ajoute un détecteur à l'analyseur."""
        self.detectors.append(detector)
        
    def process_packet(self, packet) -> None:
        """Traite un paquet : met à jour les stats et notifie les détecteurs."""
        self.total_packets += 1
        
        # Extraction basique pour l'affichage
        src_ip = ""
        dst_ip = ""
        proto_name = "Other"
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = packet[scapy.IP].proto
            if proto == 1:
                proto_name = "ICMP"
            elif proto == 6:
                proto_name = "TCP"
            elif proto == 17:
                proto_name = "UDP"
                if packet.haslayer(scapy.DNS):
                    proto_name = "DNS"
        elif packet.haslayer(scapy.ARP):
            proto_name = "ARP"
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            
        self.protocols[proto_name] += 1
        
        # Mémoriser pour l'affichage en temps réel (garde les 20 derniers max)
        self.recent_packets.append({
            "timestamp": time.time(),
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto_name,
            "length": len(packet)
        })
        if len(self.recent_packets) > 20:
            self.recent_packets.pop(0)
            
        # Notification des détecteurs
        for detector in self.detectors:
            try:
                alert = detector.analyze(packet)
                if alert:
                    self.alerts.append(alert)
            except Exception:
                # Ignorer les erreurs d'un détecteur pour ne pas bloquer les autres
                pass
