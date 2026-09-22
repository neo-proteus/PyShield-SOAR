# PyShield

## Python-Based Security Orchestration, Automation and Response Engine

PyShield is a modular Python-based security automation engine designed to demonstrate an end-to-end defensive security workflow:

**IOC → Threat Intelligence → Risk Assessment → Decision → Response → Audit**

The project accepts an Indicator of Compromise (IOC), enriches it using threat intelligence, evaluates its risk against a configurable threshold, generates appropriate containment artifacts, and records the resulting security decision as an incident.

PyShield was built as a hands-on Blue Team security engineering project focused on automation, modularity, explainable decisions, and analyst-controlled response.

---

## Features

### IOC Ingestion

- Accepts IP addresses through the command line.
- Validates incoming indicators.
- Records the IOC type and source.

### Threat Intelligence

- Integrates with the AbuseIPDB API.
- Retrieves reputation and abuse information.
- Normalizes threat intelligence into a common structure.
- Provides a mock threat-intelligence provider for testing without an API key.

### Risk-Based Decision Engine

- Uses a configurable risk threshold.
- Supports two decisions:
  - `NO_ACTION`
  - `CONTAIN`
- Provides a reason for every decision.

### Response Generation

When an IOC meets or exceeds the configured containment threshold, PyShield generates response artifacts for analyst review.

Supported response artifacts:

- Windows firewall `.bat` script
- Linux `iptables` `.sh` script

PyShield does not automatically execute generated response scripts.

### Incident and Audit Logging

Every processed IOC is recorded as a JSON incident.

Incident records include:

- Unique incident ID
- Timestamp
- Indicator
- IOC type
- Threat-intelligence provider
- Risk score
- Decision threshold
- Decision
- Generated response artifacts