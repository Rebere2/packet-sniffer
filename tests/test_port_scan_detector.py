import pytest
import scapy.all as scapy
from detectors.port_scan import PortScanDetector

def test_port_scan_detection():
    detector = PortScanDetector(threshold=20)
    packets = scapy.rdpcap("data/samples/port_scan.pcap")
    
    alerts = []
    for p in packets:
        alert = detector.analyze(p)
        if alert:
            alerts.append(alert)
            
    assert len(alerts) == 1
    assert alerts[0].severity.value == "warning"
    assert "Scan de ports" in alerts[0].message
