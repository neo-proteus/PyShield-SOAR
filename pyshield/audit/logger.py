import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class IncidentLogger:
    """
    Records PyShield security decisions and generated
    response artifacts as JSON incident records.
    """

    def __init__(self, output_directory: str = "output/incidents"):
        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def create_incident(
        self,
        indicator: str,
        ioc_type: str,
        provider: str,
        risk_score: int,
        threshold: int,
        decision: str,
        artifacts: list[str]
    ) -> Path:
        """
        Create and persist a JSON incident record.
        """

        incident_id = self._generate_incident_id()

        incident = {
            "incident_id": incident_id,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "indicator": indicator,
            "ioc_type": ioc_type,

            "threat_intelligence": {
                "provider": provider,
                "risk_score": risk_score
            },

            "decision": {
                "threshold": threshold,
                "action": decision
            },

            "response": {
                "artifact_count": len(artifacts),
                "artifacts": artifacts
            }
        }

        incident_file = (
            self.output_directory /
            f"{incident_id}.json"
        )

        incident_file.write_text(
            json.dumps(
                incident,
                indent=4
            ),
            encoding="utf-8"
        )

        return incident_file

    @staticmethod
    def _generate_incident_id() -> str:
        """
        Generate a unique incident identifier.
        """

        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d-%H%M%S")

        unique_id = uuid4().hex[:6].upper()

        return f"PS-{timestamp}-{unique_id}"
