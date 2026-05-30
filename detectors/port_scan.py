"""Détecteur de balayage de ports (Port Scan)."""
import time
from collections import defaultdict
from typing import Dict, Set, Optional
import scapy.all as scapy

from detectors.base import BaseDetector, Alert, Severity


class PortScanDetector(BaseDetector):
    """Détecte les scans de ports (SYN scan)."""
    name = "port_scan"
    
    def __init__(self, time_window: int = 5, threshold: int = 20):
        self.time_window = time_window
        self.threshold = threshold
        # Structure: src_ip -> { "start_time": float, "ports": set(int) }
        self.scans: Dict[str, dict] = defaultdict(lambda: {"start_time": time.time(), "ports": set()})
        
    def analyze(self, packet) -> Optional[Alert]:
        """Analyse un paquet TCP pour détecter un scan SYN."""
        if not packet.haslayer(scapy.TCP) or not packet.haslayer(scapy.IP):
            return None
            
        # TCP Flags: S = SYN (0x02)
        if packet[scapy.TCP].flags == 0x02:
            src_ip = packet[scapy.IP].src
            dst_port = packet[scapy.TCP].dport
            current_time = time.time()
            
            state = self.scans[src_ip]
            
            # Réinitialisation si la fenêtre de temps est dépassée
            if current_time - state["start_time"] > self.time_window:
                state["start_time"] = current_time
                state["ports"].clear()
                
            state["ports"].add(dst_port)
            
            if len(state["ports"]) > self.threshold:
                alert = Alert(
                    severity=Severity.WARNING,
                    detector=self.name,
                    message=f"Scan de ports détecté depuis {src_ip}: > {self.threshold} ports en {self.time_window}s",
                    src_ip=src_ip,
                    dst_ip=packet[scapy.IP].dst,
                    timestamp=current_time,
                    packet_summary=packet.summary()
                )
                # Remise à zéro pour éviter le flood d'alertes
                state["ports"].clear()
                state["start_time"] = current_time
                return alert
                
        return None

    def reset(self) -> None:
        self.scans.clear()
