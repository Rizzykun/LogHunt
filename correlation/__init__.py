"""Event correlation: groups related alerts into incidents."""

from .engine import (
    Incident,
    attack_chain_rows,
    correlate,
    incident_timeline,
    incidents_to_frame,
)

__all__ = [
    "Incident",
    "attack_chain_rows",
    "correlate",
    "incident_timeline",
    "incidents_to_frame",
]
