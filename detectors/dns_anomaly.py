"""Détecteur d'anomalies DNS."""
import time
from collections import defaultdict
from typing import Dict, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert, Severity


class DnsAnomalyDetector(BaseDetector):
    """Détecte les floods DNS et requêtes suspectes."""
    name = "dns_anomaly"
    
    def __init__(self, time_window: int = 1, threshold: int = 50):
        self.time_window = time_window
        self.threshold = threshold
        # src_ip -> [timestamps]
        self.queries: Dict[str, list] = defaultdict(list)
        
    def analyze(self, packet) -> Optional[Alert]:
        """Analyse un paquet DNS."""
        if not packet.haslayer(scapy.DNS) or not packet.haslayer(scapy.IP):
            return None
            
        current_time = time.time()
        src_ip = packet[scapy.IP].src
        
        # Requête DNS
        if packet[scapy.DNS].qr == 0:
            history = self.queries[src_ip]
            # Nettoyer l'historique
            self.queries[src_ip] = [t for t in history if current_time - t <= self.time_window]
            self.queries[src_ip].append(current_time)
            
            if len(self.queries[src_ip]) > self.threshold:
                alert = Alert(
                    severity=Severity.WARNING,
                    detector=self.name,
                    message=f"Flood DNS détecté: {len(self.queries[src_ip])} requêtes/s depuis {src_ip}",
                    src_ip=src_ip,
                    dst_ip=packet[scapy.IP].dst,
                    timestamp=current_time,
                    packet_summary=packet.summary()
                )
                self.queries[src_ip].clear()
                return alert
                
        # TODO: Ajouter vérification TTL=0 pour les réponses DNS (packet[scapy.DNS].qr == 1)
                
        return None

    def reset(self) -> None:
        self.queries.clear()
