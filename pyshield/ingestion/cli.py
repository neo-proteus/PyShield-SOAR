import argparse
import ipaddress

from pyshield.models.schemas import IOC


class IOCIngestor:
    """
    Handles IOC ingestion from the command line.
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="PyShield-SOAR IOC Ingestion Engine"
        )

        self.parser.add_argument(
            "--ip",
            required=True,
            help="IPv4 or IPv6 address to investigate"
        )

        self.parser.add_argument(
            "--source",
            default="cli",
            help="Source of the alert/IOC"
        )

    def parse(self) -> IOC:
        args = self.parser.parse_args()

        self._validate_ip(args.ip)

        return IOC(
            value=args.ip,
            ioc_type="ip",
            source=args.source
        )

    @staticmethod
    def _validate_ip(value: str) -> None:
        """
        Validate that the supplied value is a legitimate IP address.
        """

        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {value}"
            ) from exc
