"""Canonical MITRE ATT&CK tactic order (spec 04 section 7.1).

The matrix, the Navigator layer and the STIX loader all agree on this one
order; it lives here so a bundle import can never reorder the matrix.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Tactic:
    """One canonical tactic: matrix position, ATT&CK id, shortname, name."""

    order_idx: int
    attack_id: str
    shortname: str
    name: str


#: The fourteen enterprise tactics, in matrix order (spec 04 section 7.1).
CANONICAL_TACTICS: tuple[Tactic, ...] = (
    Tactic(0, "TA0043", "reconnaissance", "Reconnaissance"),
    Tactic(1, "TA0042", "resource-development", "Resource Development"),
    Tactic(2, "TA0001", "initial-access", "Initial Access"),
    Tactic(3, "TA0002", "execution", "Execution"),
    Tactic(4, "TA0003", "persistence", "Persistence"),
    Tactic(5, "TA0004", "privilege-escalation", "Privilege Escalation"),
    Tactic(6, "TA0005", "defense-evasion", "Defense Evasion"),
    Tactic(7, "TA0006", "credential-access", "Credential Access"),
    Tactic(8, "TA0007", "discovery", "Discovery"),
    Tactic(9, "TA0008", "lateral-movement", "Lateral Movement"),
    Tactic(10, "TA0009", "collection", "Collection"),
    Tactic(11, "TA0011", "command-and-control", "Command and Control"),
    Tactic(12, "TA0010", "exfiltration", "Exfiltration"),
    Tactic(13, "TA0040", "impact", "Impact"),
)

#: Shortname -> matrix position.
TACTIC_ORDER: dict[str, int] = {tactic.shortname: tactic.order_idx for tactic in CANONICAL_TACTICS}

#: Shortname -> display name, used when a bundle did not name a tactic.
TACTIC_NAMES: dict[str, str] = {tactic.shortname: tactic.name for tactic in CANONICAL_TACTICS}

__all__ = ["CANONICAL_TACTICS", "TACTIC_NAMES", "TACTIC_ORDER", "Tactic"]
