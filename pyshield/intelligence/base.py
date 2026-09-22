from abc import ABC, abstractmethod

from pyshield.models.schemas import IOC, ThreatIntelResult


class ThreatIntelProvider(ABC):
    """
    Abstract interface for threat-intelligence providers.

    Any future provider must implement lookup().
    """

    @abstractmethod
    def lookup(self, ioc: IOC) -> ThreatIntelResult:
        raise NotImplementedError
