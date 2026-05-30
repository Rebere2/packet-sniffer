"""Détecteur d'ARP Spoofing."""
import time
from typing import Dict, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert, Severity


class ArpSpoofingDetector(BaseDetector):
    """Détecte si plusieurs adresses MAC revendiquent la même adresse IP."""
    name = "arp_spoofing"
    
    def __init__(self):
        # Mapping IP -> MAC
        self.ip_mac_map: Dict[str, str] = {}
        
    def analyze(self, packet) -> Optional[Alert]:
        """Analyse un paquet ARP pour détecter un conflit IP/MAC."""
        if not packet.haslayer(scapy.ARP):
            return None
            
        # Opération 2 = ARP Reply (is-at)
        if packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            
            if ip in self.ip_mac_map:
                known_mac = self.ip_mac_map[ip]
                if known_mac != mac:
                    return Alert(
                        severity=Severity.CRITICAL,
                        detector=self.name,
                        message=f"Conflit ARP: l'IP {ip} est revendiquée par {mac} (connue sous {known_mac})",
                        src_ip=ip,
                        dst_ip=None,
                        timestamp=time.time(),
                        packet_summary=packet.summary()
                    )
            else:
                self.ip_mac_map[ip] = mac
                
        return None

    def reset(self) -> None:
        self.ip_mac_map.clear()
