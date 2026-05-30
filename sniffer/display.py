"""Module d'affichage temps réel."""
import time
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live

from sniffer.analyzer import Analyzer


class Display:
    """Gère l'interface terminal avec la bibliothèque Rich."""
    
    def __init__(self, analyzer: Analyzer):
        self.analyzer = analyzer
        self.console = Console()
        self.layout = self._make_layout()
        
    def _make_layout(self) -> Layout:
        """Crée la disposition de base de l'interface."""
        layout = Layout(name="root")
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="alerts", size=10)
        )
        layout["main"].split_row(
            Layout(name="packets", ratio=3),
            Layout(name="stats", ratio=1)
        )
        return layout
        
    def _generate_header(self) -> Panel:
        """Génère le bandeau supérieur."""
        uptime = int(time.time() - self.analyzer.start_time)
        return Panel(
            f"Packet Sniffer & Anomaly Detector | Uptime: {uptime}s | Paquets capturés: {self.analyzer.total_packets}",
            style="white on blue",
            title="Dashboard"
        )
        
    def _generate_stats_table(self) -> Panel:
        """Génère le tableau des statistiques par protocole."""
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Protocole")
        table.add_column("Nombre", justify="right")
        
        for proto, count in sorted(self.analyzer.protocols.items(), key=lambda x: x[1], reverse=True):
            table.add_row(proto, str(count))
            
        return Panel(table, title="Statistiques", border_style="cyan")
        
    def _generate_packets_table(self) -> Panel:
        """Génère le tableau des derniers paquets vus."""
        table = Table(show_header=True, header_style="bold green", expand=True)
        table.add_column("Heure", justify="center")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Protocole", justify="center")
        table.add_column("Taille", justify="right")
        
        for p in self.analyzer.recent_packets:
            t = time.strftime("%H:%M:%S", time.localtime(p["timestamp"]))
            table.add_row(t, p["src"], p["dst"], p["proto"], str(p["length"]))
            
        return Panel(table, title="Trafic en temps réel", border_style="green")
        
    def _generate_alerts_table(self) -> Panel:
        """Génère le panneau des alertes de sécurité."""
        table = Table(show_header=True, header_style="bold red", expand=True)
        table.add_column("Sévérité", justify="center")
        table.add_column("Heure", justify="center")
        table.add_column("Détecteur")
        table.add_column("Message")
        
        # Affiche les 10 dernières alertes pour mieux remplir l'espace
        for alert in reversed(self.analyzer.alerts[-10:]):
            t = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
            style = "bold red" if alert.severity.value == "critical" else "yellow"
            table.add_row(
                f"[{style}]{alert.severity.name}[/{style}]",
                t,
                alert.detector,
                alert.message
            )
            
        return Panel(table, title="Alertes", border_style="red")
        
    def render(self) -> Layout:
        """Met à jour et retourne le layout complet."""
        self.layout["header"].update(self._generate_header())
        self.layout["stats"].update(self._generate_stats_table())
        self.layout["packets"].update(self._generate_packets_table())
        self.layout["alerts"].update(self._generate_alerts_table())
        return self.layout
        
    def run(self, live_view: Optional[Live] = None) -> None:
        """Si nécessaire, on peut l'utiliser pour un rafraîchissement manuel."""
        pass
