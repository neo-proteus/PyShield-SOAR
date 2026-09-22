from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IOC:
    """
    Represents an Indicator of Compromise.
    """

    value: str
    ioc_type: str = "ip"
    source: str = "cli"


@dataclass
class ThreatIntelResult:
    """
    Normalized threat-intelligence result.
    """

    indicator: str
    provider: str
    risk_score: int
    malicious: bool

    confidence: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    reports: Optional[int] = None

    raw: dict = field(default_factory=dict)
