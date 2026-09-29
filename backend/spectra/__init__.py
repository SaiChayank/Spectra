"""Spectra - next-generation encrypted traffic threat detection.

Pipeline: capture -> TLS/flow metadata parsing -> feature extraction -> ML detection.
Only metadata is processed; payload contents are never inspected or stored.
"""

__version__ = "1.0.0rc1"
