"""Flow feature extraction.

Each completed flow becomes a fixed-length numeric vector consumed by the
detector. Features are derived from packet statistics, inter-arrival timing,
TLS handshake metadata, and endpoint context - never from payload contents.
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np

from ..parse.flow import Flow

SIZE_BUCKETS = 16

FEATURE_NAMES: list[str] = [
    # timing / volume
    "duration_s",
    "packets_total",
    "packets_fwd",
    "packets_bwd",
    "bytes_total",
    "bytes_fwd",
    "bytes_bwd",
    "bytes_mean",
    "bytes_std",
    "bytes_min",
    "bytes_max",
    "fwd_bwd_pkt_ratio",
    "fwd_bwd_byte_ratio",
    "iat_mean_s",
    "iat_std_s",
    "iat_min_s",
    "iat_max_s",
    "iat_fwd_mean_s",
    "iat_fwd_std_s",
    "iat_fwd_mad_s",
    "packets_per_s",
    "bytes_per_s",
    # flags
    "syn_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "payload_ratio",
    "size_entropy",
    # context
    "is_tcp",
    "dst_port_norm",
    # TLS metadata
    "tls_present",
    "tls_version_norm",
    "tls_cipher_count",
    "tls_extension_count",
    "sni_present",
    "sni_length",
    "alpn_count",
    "handshake_ms",
    "server_hello_ms",
]

N_FEATURES = len(FEATURE_NAMES)


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _ratio(a: float, b: float) -> float:
    """Order-independent ratio in [0, 1]: min/max."""
    if a == 0 and b == 0:
        return 0.0
    lo, hi = (a, b) if a <= b else (b, a)
    return _safe_div(lo, hi)


def _entropy(values: list[float], buckets: int = SIZE_BUCKETS) -> float:
    if not values:
        return 0.0
    top = max(values) or 1
    counts = Counter(min(buckets - 1, int(v / top * buckets)) for v in values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _mad(values: list[float]) -> float:
    """Median absolute deviation - robust periodicity indicator.

    C2 beacons repeat on a fixed interval, so their MAD collapses toward zero
    even with a noisy handshake at the start of the flow.
    """
    if not values:
        return 0.0
    arr = np.asarray(values, dtype=np.float64)
    med = float(np.median(arr))
    return float(np.median(np.abs(arr - med)))


def extract_features(flow: Flow) -> np.ndarray:
    pkts = flow.packets
    n = len(pkts)
    sizes = [float(p.size) for p in pkts]
    iats = [pkts[i].ts - pkts[i - 1].ts for i in range(1, n) if pkts[i].ts >= pkts[i - 1].ts]
    duration = flow.duration

    tls = flow.tls
    sni = tls.sni if tls else ""
    fwd_times = [p.ts for p in pkts if p.direction == 0]
    fwd_iats = [b - a for a, b in zip(fwd_times, fwd_times[1:]) if b >= a]
    version = 0.0
    if tls:
        effective = tls.negotiated_version or tls.legacy_version or 0
        version = effective / 0x0304  # normalize TLS versions into ~[0.85, 1.0]

    handshake_ms = 0.0
    if flow.client_hello_ts:
        handshake_ms = max(0.0, (flow.client_hello_ts - flow.start_ts) * 1000.0)
    server_ms = 0.0
    if flow.server_hello_ts:
        server_ms = max(0.0, (flow.server_hello_ts - flow.start_ts) * 1000.0)

    feats = [
        duration,
        n,
        flow.packets_fwd,
        flow.packets_bwd,
        flow.bytes_fwd + flow.bytes_bwd,
        flow.bytes_fwd,
        flow.bytes_bwd,
        float(np.mean(sizes)) if sizes else 0.0,
        float(np.std(sizes)) if sizes else 0.0,
        float(np.min(sizes)) if sizes else 0.0,
        float(np.max(sizes)) if sizes else 0.0,
        _ratio(flow.packets_fwd, flow.packets_bwd),
        _ratio(flow.bytes_fwd, flow.bytes_bwd),
        float(np.mean(iats)) if iats else 0.0,
        float(np.std(iats)) if iats else 0.0,
        float(np.min(iats)) if iats else 0.0,
        float(np.max(iats)) if iats else 0.0,
        float(np.mean(fwd_iats)) if fwd_iats else 0.0,
        float(np.std(fwd_iats)) if fwd_iats else 0.0,
        _mad(fwd_iats),
        _safe_div(n, duration),
        _safe_div(flow.bytes_fwd + flow.bytes_bwd, duration),
        float(sum(p.syn for p in pkts)),
        float(sum(p.fin for p in pkts)),
        float(sum(p.rst for p in pkts)),
        float(sum(p.psh for p in pkts)),
        _safe_div(sum(p.payload for p in pkts), flow.bytes_fwd + flow.bytes_bwd),
        _entropy(sizes),
        1.0 if flow.is_tcp else 0.0,
        flow.dst_port / 65535.0,
        1.0 if tls else 0.0,
        version,
        float(tls.cipher_count) if tls else 0.0,
        float(tls.extension_count) if tls else 0.0,
        1.0 if sni else 0.0,
        float(len(sni)),
        float(len(tls.alpn)) if tls else 0.0,
        handshake_ms,
        server_ms,
    ]
    if len(feats) != N_FEATURES:  # pragma: no cover - guards feature drift
        raise AssertionError(f"feature vector length {len(feats)} != {N_FEATURES}")
    return np.nan_to_num(np.asarray(feats, dtype=np.float32), nan=0.0, posinf=0.0, neginf=0.0)


def flows_to_matrix(flows: list[Flow]) -> np.ndarray:
    if not flows:
        return np.empty((0, N_FEATURES), dtype=np.float32)
    return np.stack([extract_features(f) for f in flows])
