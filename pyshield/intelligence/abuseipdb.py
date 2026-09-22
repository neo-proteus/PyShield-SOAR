import requests

from pyshield.intelligence.base import ThreatIntelProvider
from pyshield.models.schemas import IOC, ThreatIntelResult


class AbuseIPDBProvider(ThreatIntelProvider):

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: str,
        timeout: int = 10
    ):
        self.api_key = api_key
        self.timeout = timeout

    def lookup(self, ioc: IOC) -> ThreatIntelResult:

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }

        params = {
            "ipAddress": ioc.value,
            "maxAgeInDays": 90
        }

        try:

            response = requests.get(
                self.API_URL,
                headers=headers,
                params=params,
                timeout=self.timeout
            )

            response.raise_for_status()

            payload = response.json()

        except requests.exceptions.Timeout as exc:

            raise RuntimeError(
                "AbuseIPDB request timed out."
            ) from exc

        except requests.exceptions.HTTPError as exc:

            raise RuntimeError(
                f"AbuseIPDB returned HTTP {response.status_code}."
            ) from exc

        except requests.exceptions.RequestException as exc:

            raise RuntimeError(
                f"AbuseIPDB request failed: {exc}"
            ) from exc

        data = payload.get("data", {})

        risk_score = int(
            data.get("abuseConfidenceScore", 0)
        )

        return ThreatIntelResult(
            indicator=ioc.value,
            provider="AbuseIPDB",
            risk_score=risk_score,
            malicious=risk_score > 0,
            confidence=risk_score,
            country=data.get("countryCode"),
            isp=data.get("isp"),
            reports=data.get("totalReports"),
            raw=payload
        )
