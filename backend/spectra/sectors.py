"""Sector classification and sensitivity scoring.

Maps observed endpoints (SNI/hostname) to Spectra's three target verticals so
reports, roadmaps and (later) the cross-domain graph can be sector-aware.
Organizations can override the defaults with a JSON file:

    {"fintech": ["mybank.com"], "healthcare": ["clinic.example"]}
"""

from __future__ import annotations

import json
import os

SECTOR_FINTECH = "fintech"
SECTOR_HEALTHCARE = "healthcare"
SECTOR_SMART_CITY = "smart_city"
SECTOR_GENERAL = "general"

DEFAULT_KEYWORDS: dict[str, list[str]] = {
    SECTOR_FINTECH: [
        "bank", "pay", "fin", "visa", "mastercard", "stripe", "paypal", "trading",
        "wallet", "upi", "swift", "coin", "invest", "securities", "atm", "billing",
    ],
    SECTOR_HEALTHCARE: [
        "health", "med", "hospital", "hipaa", "ehr", "pharma", "clinic", "care",
        "patient", "diagnos", "radiol", "laborator", "bio",
    ],
    SECTOR_SMART_CITY: [
        "city", "traffic", "iot", "sensor", "grid", "water", "transport", "metro",
        "scada", "utility", "signal", "smart", "parking", "waste", "power", "energy",
    ],
}

# Regulatory weight used by the HNDL and roadmap scoring (0..1).
SENSITIVITY: dict[str, float] = {
    SECTOR_HEALTHCARE: 1.0,   # HIPAA
    SECTOR_FINTECH: 0.9,      # PCI-DSS / SOX
    SECTOR_SMART_CITY: 0.7,   # safety-critical infrastructure
    SECTOR_GENERAL: 0.4,
}


class SectorClassifier:
    def __init__(self, overrides: dict[str, list[str]] | None = None,
                 config_path: str | None = None):
        self.keywords = {k: list(v) for k, v in DEFAULT_KEYWORDS.items()}
        if config_path and os.path.isfile(config_path):
            try:
                with open(config_path, encoding="utf-8") as fh:
                    self.merge(json.load(fh))
            except (OSError, json.JSONDecodeError):
                pass  # an unreadable override must not break detection
        if overrides:
            self.merge(overrides)

    def merge(self, extra: dict[str, list[str]]) -> None:
        for sector, words in extra.items():
            if sector in self.keywords and isinstance(words, list):
                self.keywords[sector].extend(str(w).lower() for w in words)

    def classify(self, name: str | None) -> str:
        """Classify a hostname/SNI (case-insensitive keyword match)."""
        if not name:
            return SECTOR_GENERAL
        low = str(name).lower()
        # Longest keyword match wins ties in favour of the most specific signal.
        best, best_len = SECTOR_GENERAL, 0
        for sector, words in self.keywords.items():
            for word in words:
                if word in low and len(word) > best_len:
                    best, best_len = sector, len(word)
        return best

    def sensitivity(self, name: str | None) -> float:
        return SENSITIVITY[self.classify(name)]


_default: SectorClassifier | None = None


def get_classifier() -> SectorClassifier:
    global _default
    if _default is None:
        _default = SectorClassifier()
    return _default
