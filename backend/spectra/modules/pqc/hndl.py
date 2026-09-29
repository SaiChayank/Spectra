"""Harvest-Now-Decrypt-Later (HNDL) heuristics (Module 1).

An HNDL suspect is traffic that is (a) encrypted with a quantum-vulnerable
key exchange and (b) bulky and/or long-lived enough to be worth exfiltrating
today for decryption years from now. Sector sensitivity weights the verdict
(healthcare records > anonymous CDN traffic).
"""

from __future__ import annotations

import math

from ...sectors import SectorClassifier, get_classifier
from .scanner import VULNERABLE_BELOW

# Defaults tuned for enterprise egress monitoring; all overridable.
DEFAULT_MIN_BYTES = 10_000_000        # 10 MB
DEFAULT_MIN_DURATION = 30.0           # seconds
DEFAULT_MIN_RATE_BPS = 200_000        # 200 kbit/s sustained


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def assess_hndl(
    record: dict,
    assessment: dict,
    classifier: SectorClassifier | None = None,
    min_bytes: float = DEFAULT_MIN_BYTES,
    min_duration: float = DEFAULT_MIN_DURATION,
    min_rate_bps: float = DEFAULT_MIN_RATE_BPS,
) -> dict | None:
    """Return an HNDL finding, or None when the flow is not a candidate."""
    if not assessment.get("applicable"):
        return None
    score = assessment.get("score")
    if score is None or not assessment.get("quantum_vulnerable"):
        return None

    total_bytes = int(record.get("bytes") or 0)
    duration = float(record.get("duration") or 0.0)
    rate_bps = (total_bytes * 8 / duration) if duration > 0 else 0.0

    bulk = total_bytes >= min_bytes
    sustained = duration >= min_duration and rate_bps >= min_rate_bps
    if not (bulk or sustained):
        return None

    classifier = classifier or get_classifier()
    sni = record.get("sni")
    sector = classifier.classify(sni or record.get("dst"))
    sensitivity = classifier.sensitivity(sni or record.get("dst"))

    vuln_component = (VULNERABLE_BELOW - score) / VULNERABLE_BELOW  # 0..1
    volume_component = _clamp(math.log10(max(total_bytes, 1) / min_bytes + 1) / 3)
    duration_component = _clamp(duration / 3600.0)
    hndl_score = round(100 * (
        0.35 * vuln_component
        + 0.25 * volume_component
        + 0.15 * duration_component
        + 0.25 * sensitivity
    ))

    level = "high" if hndl_score >= 70 else "medium" if hndl_score >= 40 else "low"
    reasons = [
        f"quantum-vulnerable {assessment.get('kx', {}).get('name', 'unknown')} "
        f"key exchange (readiness {score}/100)",
        f"{total_bytes:,} bytes over {duration:.1f}s "
        f"({rate_bps / 1000:.0f} kbit/s sustained)",
        f"sector: {sector} (sensitivity {sensitivity:.1f})",
    ]
    if bulk:
        reasons.append("bulk transfer above the exfiltration threshold")
    if sustained:
        reasons.append("long-lived sustained flow typical of staged collection")

    return {
        "endpoint": sni or (record.get("dst") or "").rsplit(":", 1)[0],
        "src": record.get("src"),
        "dst": record.get("dst"),
        "sector": sector,
        "bytes": total_bytes,
        "duration": duration,
        "rate_bps": round(rate_bps, 1),
        "quantum_readiness": score,
        "score": hndl_score,
        "level": level,
        "detected_at": record.get("last_ts"),
        "reasons": reasons,
    }


def screen_flows(records_and_assessments, **thresholds) -> list[dict]:
    """Screen an iterable of (record, assessment) pairs."""
    findings = []
    for record, assessment in records_and_assessments:
        finding = assess_hndl(record, assessment, **thresholds)
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings
