from dataclasses import dataclass
from enum import Enum

from pyshield.models.schemas import ThreatIntelResult


class Decision(str, Enum):
    """
    Possible actions produced by the PyShield decision engine.
    """

    NO_ACTION = "NO_ACTION"
    CONTAIN = "CONTAIN"


@dataclass
class DecisionResult:
    """
    Represents the result of the security decision.
    """

    decision: Decision
    risk_score: int
    threshold: int
    reason: str


class DecisionEngine:
    """
    Evaluates threat-intelligence results against
    a configurable risk threshold.
    """

    def __init__(self, threshold: int = 80):
        if not 0 <= threshold <= 100:
            raise ValueError(
                "Decision threshold must be between 0 and 100."
            )

        self.threshold = threshold

    def evaluate(
        self,
        threat_result: ThreatIntelResult
    ) -> DecisionResult:

        risk_score = threat_result.risk_score

        if risk_score >= self.threshold:

            return DecisionResult(
                decision=Decision.CONTAIN,
                risk_score=risk_score,
                threshold=self.threshold,
                reason=(
                    f"Risk score {risk_score} meets or exceeds "
                    f"the containment threshold of {self.threshold}."
                )
            )

        return DecisionResult(
            decision=Decision.NO_ACTION,
            risk_score=risk_score,
            threshold=self.threshold,
            reason=(
                f"Risk score {risk_score} is below "
                f"the containment threshold of {self.threshold}."
            )
        )
