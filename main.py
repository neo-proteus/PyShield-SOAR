import json
import os
from pathlib import Path

from dotenv import load_dotenv

from pyshield.audit.logger import IncidentLogger
from pyshield.response.generator import ResponseGenerator
from pyshield.decision.engine import DecisionEngine
from pyshield.ingestion.cli import IOCIngestor
from pyshield.intelligence.abuseipdb import AbuseIPDBProvider
from pyshield.intelligence.mock import MockThreatIntelProvider


def load_config() -> dict:
    """
    Load application configuration.
    """

    config_path = Path("config/config.json")

    with config_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def print_result(result):
    """
    Display normalized threat-intelligence data.
    """

    print()
    print("=" * 50)
    print("          PYSHIELD-SOAR INTELLIGENCE")
    print("=" * 50)

    print(f"Indicator : {result.indicator}")
    print(f"Provider  : {result.provider}")
    print(f"Risk      : {result.risk_score}/100")
    print(f"Malicious : {result.malicious}")
    print(f"Confidence: {result.confidence}")
    print(f"Country   : {result.country}")
    print(f"ISP       : {result.isp}")
    print(f"Reports   : {result.reports}")

    print("=" * 50)
    print()


def main():

    load_dotenv()

    config = load_config()

    # -------------------------
    # 1. INGEST IOC
    # -------------------------

    ingestor = IOCIngestor()

    try:
        ioc = ingestor.parse()

    except ValueError as exc:

        print(f"[ERROR] {exc}")
        return

    print(f"[+] IOC received: {ioc.value}")
    print(f"[+] IOC type: {ioc.ioc_type}")
    print(f"[+] IOC source: {ioc.source}")

    # -------------------------
    # 2. SELECT THREAT INTELLIGENCE PROVIDER
    # -------------------------

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    provider_config = config["threat_intelligence"]

    if api_key:

        provider = AbuseIPDBProvider(
            api_key=api_key,
            timeout=provider_config["timeout"]
        )

        print("[+] Threat Intelligence: AbuseIPDB")

    else:

        provider = MockThreatIntelProvider()

        print("[!] AbuseIPDB API key not configured.")
        print("[!] Using mock threat intelligence.")

    # -------------------------
    # 3. THREAT INTELLIGENCE
    # -------------------------

    try:

        result = provider.lookup(ioc)

    except RuntimeError as exc:

        print(f"[ERROR] {exc}")
        return

    # -------------------------
    # 4. DISPLAY RESULT
    # -------------------------

    print_result(result)

    # -------------------------
    # 5. DECISION ENGINE
    # -------------------------

    decision_config = config["decision"]

    decision_engine = DecisionEngine(
        threshold=decision_config["containment_threshold"]
    )

    decision = decision_engine.evaluate(result)

    print()
    print("=" * 50)
    print("             PYSHIELD-SOAR DECISION")
    print("=" * 50)

    print(f"Risk Score : {decision.risk_score}/100")
    print(f"Threshold  : {decision.threshold}")
    print(f"Decision   : {decision.decision.value}")
    print(f"Reason     : {decision.reason}")

    print("=" * 50)

    # -------------------------
    # 6. RESPONSE GENERATION
    # -------------------------

    response_generator = ResponseGenerator(
        output_directory="output"
    )

    artifacts = response_generator.generate(
        indicator=ioc.value,
        decision=decision.decision
    )

    print()
    print("=" * 50)
    print("          PYSHIELD-SOAR RESPONSE")
    print("=" * 50)

    if artifacts:

        print("[+] Containment artifacts generated:")

        for artifact in artifacts:
            print(f"    - {artifact}")

    else:

        print("[+] No containment required.")
        print("[+] No response artifacts generated.")

    print("=" * 50)

    # -------------------------
    # 7. AUDIT / INCIDENT LOG
    # -------------------------

    incident_logger = IncidentLogger()

    artifact_paths = [
        str(artifact)
        for artifact in artifacts
    ]

    incident_file = incident_logger.create_incident(
        indicator=ioc.value,
        ioc_type=ioc.ioc_type,
        provider=result.provider,
        risk_score=result.risk_score,
        threshold=decision.threshold,
        decision=decision.decision.value,
        artifacts=artifact_paths
    )

    print()
    print("=" * 50)
    print("          PYSHIELD-SOAR AUDIT")
    print("=" * 50)

    print(f"[+] Incident recorded: {incident_file}")

    print("=" * 50)


if __name__ == "__main__":
    main()