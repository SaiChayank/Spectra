"""Alert severity: an ordinal triage level, deliberately **not** the score.

Severity answers *"how urgently should an analyst look at this?"* — a
different question from the detector's *anomaly score* (how far the flow sits
from the training distribution), the classifier's *confidence* (how much of
the evidence supports the chosen category), and the *threat type* (which
behaviour it resembles).  The four concepts ride side by side on every alert
(:class:`spectra.domain.ThreatAlert`), and severity is derived from all of
them without ever being equal to any one of them.

Calculation (documented rule table, applied in order)
-----------------------------------------------------
Severity is an **ordinal level** — ``LOW < MEDIUM < HIGH < CRITICAL`` — not a
fabricated numeric score; the resolution the evidence does not support is
not pretended.  Five inputs decide it:

1. **Threat category → base level** (what kind of behaviour this is)::

       C2_BEACONING, DATA_EXFILTRATION_SUSPECTED  -> HIGH
       RECONNAISSANCE, VOLUMETRIC_ANOMALY,
       UNUSUAL_ENDPOINT_BEHAVIOR                  -> MEDIUM
       TLS_ANOMALY, QUIC_ANOMALY, UNKNOWN_ANOMALY  -> LOW

2. **Confidence** (classifier evidence share): ``>= 0.85`` raises one level
   (a classification the evidence stands behind); ``< 0.50`` lowers one level
   (thin evidence — unknown verdicts stay modest); in between, no change.

3. **Anomaly intensity**: a detector score ``>= 99`` (the top band of the
   0-100 percentile scale — every alert is already flagged) raises one level;
   a lower score or an unavailable score does not.

4. **Affected asset context, where available**: a critical asset (sensitive
   sector per :mod:`spectra.sectors`, or an internal host on an
   administrative port) raises one level.  ``internal`` (ordinary private
   host) and *unknown* context contribute no change and are honestly
   reported as such — absence of asset information is never read as safety.

5. **Correlation/context**: the same behaviour grouped into this alert
   ``>= 3`` times raises one level (repetition is escalation); a first
   sighting does not.

The result is clamped to ``[LOW, CRITICAL]``.  Every input — including the
ones that did not change the outcome — is returned in the factors list, so an
alert always shows *why* its severity is what it is.
"""

from __future__ import annotations

#: The ordinal levels, weakest first.  Ordering is the only precision claimed.
SEVERITIES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

#: Step 1 — category base level (unknown categories stay modest: LOW).
_CATEGORY_BASE: dict[str, str] = {
    "C2_BEACONING": SEVERITY_HIGH,
    "DATA_EXFILTRATION_SUSPECTED": SEVERITY_HIGH,
    "RECONNAISSANCE": SEVERITY_MEDIUM,
    "VOLUMETRIC_ANOMALY": SEVERITY_MEDIUM,
    "UNUSUAL_ENDPOINT_BEHAVIOR": SEVERITY_MEDIUM,
    "TLS_ANOMALY": SEVERITY_LOW,
    "QUIC_ANOMALY": SEVERITY_LOW,
    "UNKNOWN_ANOMALY": SEVERITY_LOW,
}

#: Step 2 — confidence bands (classifier evidence share, 0-1).
CONFIDENCE_ESCALATE = 0.85
CONFIDENCE_ATTENUATE = 0.50

#: Step 3 — detector score (0-100 percentile) top band.
SCORE_INTENSITY = 99.0

#: Step 5 — correlated sightings that count as repetition.
CORRELATION_REPEATS = 3

#: Step 4 — asset criticality values understood by the calculation.
ASSET_CRITICAL = "critical"       # sensitive sector or internal admin service
ASSET_INTERNAL = "internal"       # ordinary private-network host
#: anything else (including None) = no usable asset context


def calculate_severity(*, threat_type: str, confidence: float,
                       anomaly_score: float | None = None,
                       asset_criticality: str | None = None,
                       occurrences: int = 1) -> tuple[str, list[str]]:
    """Derive the alert's ordinal severity plus its full derivation.

    Parameters
    ----------
    threat_type:
        The classified category (see ``spectra.threats.THREAT_TYPES``).
    confidence:
        Classifier evidence share for that category (0-1).
    anomaly_score:
        Detector score (0-100 percentile), or ``None`` when unavailable.
    asset_criticality:
        ``"critical"`` / ``"internal"`` / ``None`` — see module docstring.
    occurrences:
        How many sightings are grouped into this alert (>= 1).

    Returns
    -------
    ``(severity, factors)`` where ``severity`` is one of :data:`SEVERITIES`
    and ``factors`` lists every input's contribution in human-readable form
    (including "no change" inputs) — the alert persists this list so the
    level can always be justified without re-running the pipeline.

    Examples
    --------
    >>> calculate_severity(threat_type="C2_BEACONING", confidence=0.95,
    ...                    anomaly_score=99.4)[0]
    'CRITICAL'
    >>> calculate_severity(threat_type="UNKNOWN_ANOMALY", confidence=0.3,
    ...                    anomaly_score=99.4)[0]
    'LOW'
    >>> calculate_severity(threat_type="TLS_ANOMALY", confidence=0.9,
    ...                    anomaly_score=96.0)[0]
    'MEDIUM'
    """
    base = _CATEGORY_BASE.get(threat_type)
    if base is None:
        base = SEVERITY_LOW
        factors = [f"threat category {threat_type} unknown -> base LOW"]
    else:
        factors = [f"threat category {threat_type} -> base {base}"]
    level = SEVERITIES.index(base)

    # Step 2: confidence raises/lowers one level (or does nothing).
    if confidence >= CONFIDENCE_ESCALATE:
        level += 1
        factors.append(
            f"confidence {confidence:.2f} >= {CONFIDENCE_ESCALATE:.2f} "
            "-> raised one level")
    elif confidence < CONFIDENCE_ATTENUATE:
        level -= 1
        factors.append(
            f"confidence {confidence:.2f} < {CONFIDENCE_ATTENUATE:.2f} "
            "-> lowered one level (thin evidence)")
    else:
        factors.append(
            f"confidence {confidence:.2f} in the ordinary band -> no change")

    # Step 3: anomaly intensity (top band only — all alerts are flagged).
    if anomaly_score is None:
        factors.append("anomaly intensity unavailable -> no change")
    elif anomaly_score >= SCORE_INTENSITY:
        level += 1
        factors.append(
            f"anomaly intensity {anomaly_score:.1f} >= {SCORE_INTENSITY:g} "
            "-> raised one level")
    else:
        factors.append(
            f"anomaly intensity {anomaly_score:.1f} below the top band "
            "-> no change")

    # Step 4: affected asset context, honest about its absence.
    if asset_criticality == ASSET_CRITICAL:
        level += 1
        factors.append("affected asset is critical "
                       "(sensitive sector or internal admin service) "
                       "-> raised one level")
    elif asset_criticality == ASSET_INTERNAL:
        factors.append("affected asset is internal (ordinary service) "
                       "-> no change")
    else:
        factors.append("no asset context available -> no change")

    # Step 5: correlation (grouped repetition of the same behaviour).
    if occurrences >= CORRELATION_REPEATS:
        level += 1
        factors.append(f"same behaviour seen {occurrences} times "
                       "(correlated) -> raised one level")
    else:
        factors.append(f"{occurrences} sighting(s) of this behaviour "
                       "-> no change")

    clamped = min(max(level, 0), len(SEVERITIES) - 1)
    if clamped != level:
        factors.append(f"clamped to {SEVERITIES[clamped]} "
                       "(severity is ordinal: LOW..CRITICAL)")
    return SEVERITIES[clamped], factors


__all__ = [
    "ASSET_CRITICAL",
    "ASSET_INTERNAL",
    "CONFIDENCE_ATTENUATE",
    "CONFIDENCE_ESCALATE",
    "CORRELATION_REPEATS",
    "SCORE_INTENSITY",
    "SEVERITIES",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "calculate_severity",
]
