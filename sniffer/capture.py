"""Module de capture réseau."""
import threading
from typing import Optional, Callable
import scapy.all as scapy

from sniffer.analyzer import Analyzer


class Capture:
    """Classe responsable de la capture des paquets réseau."""
    
    def __init__(self, analyzer: Analyzer, interface: Optional[str] = None, pcap_file: Optional[str] = None, bpf_filter: str = ""):
        self.analyzer = analyzer
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        
    def _packet_handler(self, packet) -> None:
        """Fonction appelée pour chaque paquet capturé."""
        self.analyzer.process_packet(packet)
        
    def _sniff_live(self) -> None:
        """Capture depuis une interface réseau."""
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception as e:
            # En production, on loggerait l'erreur
            pass
            
    def _sniff_offline(self) -> None:
        """Lecture depuis un fichier pcap (mode demo)."""
        try:
            scapy.sniff(
                offline=self.pcap_file,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Exception:
            pass
            
    def start(self) -> None:
        """Démarre la capture dans un thread séparé."""
        self.stop_event.clear()
        target = self._sniff_offline if self.pcap_file else self._sniff_live
        self.capture_thread = threading.Thread(target=target, daemon=True)
        self.capture_thread.start()
        
    def stop(self) -> None:
        """Arrête la capture réseau."""
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
