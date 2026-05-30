"""Détecteur basé sur des listes noires (Threat Intel)."""
import os
import time
from typing import Set, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert, Severity


class ThreatIntelDetector(BaseDetector):
    """Vérifie les adresses IP contre une liste d'IPs malveillantes."""
    name = "threat_intel"
    
    def __init__(self, blacklist_file: str = "data/blacklists/malicious_ips.txt"):
        self.malicious_ips: Set[str] = set()
        self._load_blacklist(blacklist_file)
        
    def _load_blacklist(self, filepath: str) -> None:
        """Charge la liste noire depuis le fichier s'il existe."""
        if not os.path.exists(filepath):
            return
            
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.malicious_ips.add(line)
        except Exception:
            pass
            
    def analyze(self, packet) -> Optional[Alert]:
        """Vérifie si les IPs source ou destination sont malveillantes."""
        if not packet.haslayer(scapy.IP):
            return None
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        malicious = None
        direction = ""
        
        if src_ip in self.malicious_ips:
            malicious = src_ip
            direction = "Source"
        elif dst_ip in self.malicious_ips:
            malicious = dst_ip
            direction = "Destination"
            
        if malicious:
            return Alert(
                severity=Severity.CRITICAL,
                detector=self.name,
                message=f"IP malveillante détectée en {direction}: {malicious}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                timestamp=time.time(),
                packet_summary=packet.summary()
            )
            
        return None

    def reset(self) -> None:
        pass
