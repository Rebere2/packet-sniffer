"""Module contenant les définitions de base des détecteurs."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Niveaux de sévérité des alertes."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Modèle de données d'une alerte de sécurité."""
    severity: Severity
    detector: str
    message: str
    src_ip: str
    dst_ip: Optional[str]
    timestamp: float
    packet_summary: str


class BaseDetector:
    """Classe de base pour tous les détecteurs d'anomalies."""
    name: str = "base"

    def analyze(self, packet) -> Optional[Alert]:
        """Analyse un paquet et retourne une alerte si une anomalie est détectée."""
        raise NotImplementedError

    def reset(self) -> None:
        """Remet à zéro l'état interne du détecteur."""
        pass
