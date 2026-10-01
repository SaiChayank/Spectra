"""Structured evidence for analyst alerts: machine- and human-readable.

An alert must be understandable *without* re-running the pipeline, at two
levels:

* **Technical evidence** — one item per behavioural signal with a stable
  machine-readable ``key``, its measured ``value`` and ``unit``, a human
  ``label`` and the original ``detail`` phrasing, e.g.::

      periodicity        = 30.2 s
      timing_mad         = 0.7 s
      outbound_ratio     = 8.3 ratio
      destination_first_seen = true

* **Analyst summary** — one plain sentence explaining what happened, e.g.
  *"Connections repeated approximately every 30 seconds with unusually
  stable timing."*

Items are derived from the classifier's signals (``spectra.threats``), whose
``value``/``unit`` carry the measurement behind each signal; contradicting
signals are kept in a separate list so the evidence stays balanced.  The
summary prefers a numeric template for the category (filled only when every
measurement it needs is present — no invented numbers) and otherwise states
the category's documented behaviour description.
"""

from __future__ import annotations

import string

from .threats import UNKNOWN

#: Signal name -> evidence key, where the analyst-facing name differs.
_KEY_OVERRIDES: dict[str, str] = {
    "periodic_forward_timing": "periodicity",
    "low_timing_mad": "timing_mad",
    "outbound_dominance": "outbound_ratio",
    "unusual_destination": "destination_first_seen",
}

#: Evidence key -> human label (anything else is derived from the key).
_LABELS: dict[str, str] = {
    "periodicity": "Periodicity",
    "timing_mad": "Timing MAD",
    "outbound_ratio": "Outbound ratio",
    "destination_first_seen": "Destination first seen",
}

#: ``key: (sentence template, ...)`` — used only when *every* placeholder has
#: a measured value (placeholders are discovered by parsing the template, so
#: a sentence can never reference an absent measurement).
_TEMPLATES: dict[str, str] = {
    "C2_BEACONING": (
        "Connections repeated approximately every {periodicity:.0f} seconds "
        "with unusually stable timing."
    ),
    "RECONNAISSANCE": (
        "Source contacted {destination_fanout} distinct destinations and "
        "{many_short_flows:.0%} of its recent flows were short-lived - "
        "scanning-like behaviour."
    ),
    "DATA_EXFILTRATION_SUSPECTED": (
        "Outbound traffic was {outbound_ratio:.1f}x the inbound volume over "
        "a sustained transfer - suspected data exfiltration."
    ),
    "VOLUMETRIC_ANOMALY": (
        "Transfer rate reached {extreme_throughput:.1f} MB/s - extreme for "
        "this environment."
    ),
    "UNUSUAL_ENDPOINT_BEHAVIOR": (
        "Traffic to this endpoint was {behavior_change:.1f}x its usual "
        "volume - a known endpoint acting out of character."
    ),
}

#: Category behaviour descriptions, used when no template's measurements are
#: all present (honest general phrasing, never a fabricated number).
_DESCRIPTIONS: dict[str, str] = {
    "C2_BEACONING": ("Repeated connections to one destination with a steady "
                     "cadence (beacon-like behaviour)."),
    "RECONNAISSANCE": ("A source probed many destinations or ports with "
                       "mostly short-lived flows (scanning-like behaviour)."),
    "DATA_EXFILTRATION_SUSPECTED": (
        "Outbound traffic strongly dominated a sustained transfer "
        "(suspected data exfiltration)."),
    "TLS_ANOMALY": ("TLS handshake metadata deviates from ordinary clients "
                    "(version, names, fingerprints or timing)."),
    "QUIC_ANOMALY": ("QUIC handshake metadata deviates from ordinary clients "
                     "(version, names or ALPN)."),
    "VOLUMETRIC_ANOMALY": ("Transfer rate or size is extreme for this "
                           "environment."),
    "UNUSUAL_ENDPOINT_BEHAVIOR": (
        "A previously seen endpoint exchanged unusual traffic volumes or "
        "used an unexpected service port."),
    UNKNOWN: ("The detector flagged this flow, but behavioural evidence did "
              "not reach any specific threat category."),
}


def _label(key: str) -> str:
    return _LABELS.get(key, key.replace("_", " ").capitalize())


def _item(signal: dict) -> dict:
    """One signal -> one structured evidence item."""
    name = str(signal.get("signal") or "evidence")
    value = signal.get("value")
    return {
        "key": _KEY_OVERRIDES.get(name, name),
        "value": value if isinstance(value, (bool, str, int, float)) else None,
        "unit": str(signal["unit"]) if signal.get("unit") is not None else None,
        "label": _label(_KEY_OVERRIDES.get(name, name)),
        "detail": str(signal.get("detail") or ""),
    }


def _placeholders(template: str) -> set[str]:
    return {fname for _, fname, _, _ in string.Formatter().parse(template)
            if fname}


def _summary(threat: dict, values: dict) -> str:
    """The analyst sentence: numeric template when possible, else description."""
    threat_type = str(threat.get("threat_type") or UNKNOWN)
    template = _TEMPLATES.get(threat_type)
    if template is not None:
        needed = _placeholders(template)
        if needed <= values.keys():
            try:
                return template.format(**{k: values[k] for k in needed})
            except (KeyError, ValueError, TypeError):
                pass  # fall through to the description rather than fabricate
    if threat_type == UNKNOWN:
        base = _DESCRIPTIONS[UNKNOWN]
        candidate = threat.get("candidate")
        if candidate:
            base += (f" Closest sub-threshold candidate: "
                     f"{str(candidate).replace('_', ' ').lower()}.")
        return base
    return _DESCRIPTIONS.get(threat_type, _DESCRIPTIONS[UNKNOWN])


def build_evidence(record: dict, threat: dict) -> dict:
    """Turn one classification into the alert's evidence document.

    Parameters
    ----------
    record:
        The flagged flow record (adds ``source``/``destination`` names to the
        measurement context).
    threat:
        The classifier verdict (``spectra.threats.classify_threat`` output).

    Returns
    -------
    dict with ``supporting`` and ``contradicting`` evidence items
    (``key``/``value``/``unit``/``label``/``detail`` each) and a human
    ``summary`` sentence.  Never raises: a malformed signal degrades to its
    detail text.
    """
    rec = record if isinstance(record, dict) else {}
    assessment = threat if isinstance(threat, dict) else {}
    try:
        supporting = [_item(s) for s in (assessment.get("supporting") or [])
                      if isinstance(s, dict)]
        contradicting = [_item(s) for s in (assessment.get("contradicting") or [])
                         if isinstance(s, dict)]
    except Exception:  # noqa: BLE001 - evidence must never break publication
        supporting, contradicting = [], []
    values = {i["key"]: i["value"] for i in supporting
              if i["value"] is not None}
    dst = str(rec.get("dst") or "")
    if dst:
        values.setdefault("destination", dst.rpartition(":")[0] or dst)
    return {
        "supporting": supporting,
        "contradicting": contradicting,
        "summary": _summary(assessment, values),
    }


__all__ = ["build_evidence"]
