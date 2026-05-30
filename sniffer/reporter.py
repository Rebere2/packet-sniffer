"""Générateur de rapports HTML."""
import os
import time
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from sniffer.analyzer import Analyzer


class Reporter:
    """Responsable de la génération des rapports à la fin de la capture."""
    
    def __init__(self, analyzer: Analyzer, output_dir: str = "."):
        self.analyzer = analyzer
        self.output_dir = output_dir
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
    def generate_html_report(self) -> str:
        """Génère un rapport HTML complet."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        # Préparation des données pour le template
        alerts_data = []
        for alert in self.analyzer.alerts:
            alerts_data.append({
                "time_str": time.strftime("%H:%M:%S", time.localtime(alert.timestamp)),
                "severity": alert.severity.value,
                "detector": alert.detector,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "message": alert.message,
            })
            
        context = {
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": int(time.time() - self.analyzer.start_time),
            "total_packets": self.analyzer.total_packets,
            "protocols": dict(sorted(self.analyzer.protocols.items(), key=lambda x: x[1], reverse=True)),
            "alerts": alerts_data
        }
        
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("report.html.j2")
        html_content = template.render(context)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        return filepath
