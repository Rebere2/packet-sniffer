"""Détecteur de flood ICMP."""
import time
from collections import defaultdict
from typing import Dict, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert, Severity


class IcmpFloodDetector(BaseDetector):
    """Détecte un nombre anormal de paquets ICMP vers une même cible."""
    name = "icmp_flood"
    
    def __init__(self, time_window: int = 1, threshold: int = 100):
        self.time_window = time_window
        self.threshold = threshold
        # (src_ip, dst_ip) -> [timestamps]
        self.requests: Dict[tuple, list] = defaultdict(list)
        
    def analyze(self, packet) -> Optional[Alert]:
        if not packet.haslayer(scapy.ICMP) or not packet.haslayer(scapy.IP):
            return None
            
        # ICMP Echo Request (type 8)
        if packet[scapy.ICMP].type == 8:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            current_time = time.time()
            key = (src_ip, dst_ip)
            
            history = self.requests[key]
            self.requests[key] = [t for t in history if current_time - t <= self.time_window]
            self.requests[key].append(current_time)
            
            if len(self.requests[key]) > self.threshold:
                alert = Alert(
                    severity=Severity.WARNING,
                    detector=self.name,
                    message=f"ICMP Flood détecté depuis {src_ip} vers {dst_ip}: > {self.threshold}/s",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    timestamp=current_time,
                    packet_summary=packet.summary()
                )
                self.requests[key].clear()
                return alert
                
        return None

    def reset(self) -> None:
        self.requests.clear()
