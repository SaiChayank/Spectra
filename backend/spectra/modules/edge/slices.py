"""Module 8: 5G network-slice awareness.

Every flow is assigned to a slice (URLLC / eMBB / mMTC / default) from
traffic shape and sector, and slice policy differentiates how the immune
response maps onto action:

  urllc   - healthcare / industrial control: over-react, escalate alerts
            to isolate one notch earlier;
  embb    - broadband bulk transfer: standard policy;
  mmtc    - sensor / IoT fleets: mute single-flow "monitor" chatter (the
            swarm of tiny flows is the signal, not any one of them);
  default - best-effort catch-all.

Classification is pure policy over fields we already extract - no payload,
no new state, and it can never raise (a mis-shape falls back to default).
"""

from __future__ import annotations

from ...sectors import get_classifier

# slice thresholds (documented, deterministic)
EMBB_BPS = 1_000_000        # >= 1 MB/s sustained -> broadband bulk
MMTC_MAX_AVG_PKT = 128.0    # <= 128 byte average packet -> sensor chatter
MMTC_MAX_PACKETS = 64

SLICES: dict[str, dict] = {
    "urllc": {
        "label": "URLLC - ultra-reliable low latency (healthcare / ICS)",
        "sensitivity": +1,
        "policy": "escalate alert -> isolate",
        "max_rtt_ms": 10,
    },
    "embb": {
        "label": "eMBB - enhanced mobile broadband (video / bulk)",
        "sensitivity": 0,
        "policy": "standard response ladder",
        "max_rtt_ms": 50,
    },
    "mmtc": {
        "label": "mMTC - massive machine-type comms (sensor fleets)",
        "sensitivity": -1,
        "policy": "mute single-flow monitor chatter",
        "max_rtt_ms": 1000,
    },
    "default": {
        "label": "best-effort default slice",
        "sensitivity": 0,
        "policy": "standard response ladder",
        "max_rtt_ms": 150,
    },
}


def classify_slice(record: dict) -> str:
    """Map a flow record onto a slice id; never raises."""
    try:
        sector = get_classifier().classify(record.get("sni"))
        if sector == "healthcare":
            return "urllc"

        duration = float(record.get("duration") or 0.0)
        total = float(record.get("bytes") or 0.0)
        packets = float(record.get("packets") or 0.0)
        bps = total / max(duration, 1e-3)
        if bps >= EMBB_BPS:
            return "embb"

        avg_pkt = total / packets if packets else total
        if (not record.get("tls_version")
                and packets and packets <= MMTC_MAX_PACKETS
                and avg_pkt <= MMTC_MAX_AVG_PKT):
            return "mmtc"
        return "default"
    except Exception:  # noqa: BLE001 - slice tagging must never kill capture
        return "default"


def apply_slice_policy(level: int, slice_id: str) -> tuple[int, str]:
    """Differentiate the response ladder per slice.

    Returns (adjusted level, human-readable note).
    """
    try:
        level = int(level)
        slice_id = slice_id if slice_id in SLICES else "default"
        if slice_id == "urllc" and level >= 2:
            return min(3, level + 1), f"{slice_id}:+1 critical slice escalates"
        if slice_id == "mmtc" and level == 1:
            return 0, f"{slice_id}:-1 sensor chatter muted"
        return level, f"{slice_id}:unchanged"
    except Exception:  # noqa: BLE001
        return int(level), "default:unchanged"
