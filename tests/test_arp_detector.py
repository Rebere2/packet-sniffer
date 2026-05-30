import pytest
import scapy.all as scapy
from detectors.arp_spoofing import ArpSpoofingDetector

def test_arp_spoofing_detection():
    detector = ArpSpoofingDetector()
    packets = scapy.rdpcap("data/samples/arp_spoof.pcap")
    
    # Premier paquet: devrait être ignoré (enregistrement)
    alert1 = detector.analyze(packets[0])
    assert alert1 is None
    
    # Deuxième paquet avec MAC différente: devrait déclencher une alerte
    alert2 = detector.analyze(packets[1])
    assert alert2 is not None
    assert alert2.severity.value == "critical"
    assert "Conflit ARP" in alert2.message
