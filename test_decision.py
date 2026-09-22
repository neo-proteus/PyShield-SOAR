from pyshield.decision.engine import DecisionEngine
from pyshield.models.schemas import ThreatIntelResult


def main():

    engine = DecisionEngine(threshold=80)

    simulated_result = ThreatIntelResult(
        indicator="203.0.113.50",
        provider="TestProvider",
        risk_score=95,
        malicious=True,
        confidence=95,
        country="TEST",
        isp="Test ISP",
        reports=100
    )

    decision = engine.evaluate(simulated_result)

    print()
    print("=" * 50)
    print("       PYSHIELD-SOAR DECISION TEST")
    print("=" * 50)

    print(f"Risk Score : {decision.risk_score}/100")
    print(f"Threshold  : {decision.threshold}")
    print(f"Decision   : {decision.decision.value}")
    print(f"Reason     : {decision.reason}")

    print("=" * 50)


if __name__ == "__main__":
    main()