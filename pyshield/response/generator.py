from pathlib import Path

from pyshield.decision.engine import Decision


class ResponseGenerator:
    """
    Generates containment artifacts based on a security decision.

    The generated scripts are intentionally NOT executed automatically.
    They are created as response artifacts for analyst review.
    """

    def __init__(self, output_directory: str = "output"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def generate(
        self,
        indicator: str,
        decision: Decision
    ) -> list[Path]:
        """
        Generate response artifacts for the supplied IOC.

        Returns:
            A list containing the paths of generated artifacts.
        """

        if decision != Decision.CONTAIN:
            return []

        windows_script = self._generate_windows(indicator)
        linux_script = self._generate_linux(indicator)

        return [
            windows_script,
            linux_script
        ]

    def _generate_windows(
        self,
        indicator: str
    ) -> Path:

        filename = (
            self.output_directory /
            "pyshield_contain_windows.bat"
        )

        content = f"""@echo off
REM PyShield-SOAR containment artifact
REM Review before execution
REM IOC: {indicator}

netsh advfirewall firewall add rule name="PyShield-Block-IOC" dir=out action=block remoteip={indicator}

echo PyShield containment rule prepared for {indicator}
"""

        filename.write_text(
            content,
            encoding="utf-8"
        )

        return filename

    def _generate_linux(
        self,
        indicator: str
    ) -> Path:

        filename = (
            self.output_directory /
            "pyshield_contain_linux.sh"
        )

        content = f"""#!/bin/bash

# PyShield-SOAR containment artifact
# Review before execution
# IOC: {indicator}

iptables -A OUTPUT -d {indicator} -j DROP

echo "PyShield containment rule prepared for {indicator}"
"""

        filename.write_text(
            content,
            encoding="utf-8"
        )

        return filename
