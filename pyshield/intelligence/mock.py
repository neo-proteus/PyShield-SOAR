from pyshield.intelligence.base import ThreatIntelProvider
from pyshield.models.schemas import IOC, ThreatIntelResult


class MockThreatIntelProvider(ThreatIntelProvider):
    """
    Offline fallback provider used for development and testing.
    """

    def lookup(self, ioc: IOC) -> ThreatIntelResult:

        return ThreatIntelResult(
            indicator=ioc.value,
            provider="MockTI",
            risk_score=50,
            malicious=False,
            confidence=50,
            country="XX",
            isp="Simulated Provider",
            reports=0,
            raw={
                "simulation": True,
                "message": "Simulated threat-intelligence response"
            }
        )
