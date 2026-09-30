"""Module 2: Confidential Computing & TEE Integration.

Public surface:
    TeeEnclave      - measurement, nonce-bound quotes, sealed inference
    measure_file    - MRENCLAVE-style SHA-256 of a model artifact
    digest_features - feature-only input digest (payload never enters)
    federated_round - additive secret-sharing secure aggregation (full detail)
    public_report   - safe summary of a round for API/CLI consumers
    recombine       - k-of-k recombination of integer shares
"""

from .enclave import (
    TeeEnclave,
    TeeError,
    digest_features,
    digest_output,
    measure_file,
)
from .federated import FederatedError, federated_round, public_report, recombine

__all__ = [
    "FederatedError",
    "TeeEnclave",
    "TeeError",
    "digest_features",
    "digest_output",
    "federated_round",
    "measure_file",
    "public_report",
    "recombine",
]
