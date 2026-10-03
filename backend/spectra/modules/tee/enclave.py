"""Module 2: TEE-protected inference & attestation (enclave contract).

Real deployments run this inside Intel SGX / AMD SEV-SNP / ARM TrustZone.
This module implements the *contract* those enclaves provide, with the
same verification surface an auditor would use against them:

  measurement - SHA-256 over the model artifact (MRENCLAVE analog); any
                byte change to the model changes the measurement
  quote       - nonce-bound, Schnorr-signed attestation of the measurement
                (Attestation-as-a-Service: prove the model is the one
                you audited, without trusting the host)
  receipt     - sealed, signed binding of (measurement, input digest,
                output digest) so any inference can be replayed later

Privacy: the sealed input digest covers the *feature vector only* - raw
payload never enters the enclave (payload_bytes = 0), which is exactly
what the Module 5 ZK certificate claims.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid

import numpy as np

from ...features.extractor import N_FEATURES
from ..audit import canonical_json
from ..audit.curve import schnorr_keypair, schnorr_sign, schnorr_verify

QUOTE_DOMAIN = "spectra.tee.quote.v1"
RECEIPT_DOMAIN = "spectra.tee.receipt.v1"
QUOTE_MAX_AGE_S = 600.0
#: Every quote this build emits is produced by a *software* enclave (a key
#: file, not a hardware root of trust), so the label travels inside the
#: signed body: no consumer can mistake a SPECTRA quote for hardware
#: attestation, and tampering with the label breaks the signature.
#: ``/api/capabilities`` reports the same SIMULATED status for Module 2.
QUOTE_ENVIRONMENT = "SIMULATED"
#: Owner-only permissions for the attestation key file (POSIX mode bits;
#: ``os.chmod`` is best effort where the platform has none).
KEY_FILE_MODE = 0o600


class TeeError(ValueError):
    pass


def measure_file(path: str) -> str | None:
    """MRENCLAVE-style measurement of an artifact (streamed SHA-256)."""
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_features(features) -> str:
    """Digest of the feature vector only (payload bytes never enter)."""
    vals = [round(float(v), 6) for v in features]
    return hashlib.sha256(canonical_json(vals).encode("utf-8")).hexdigest()


def digest_output(output: dict) -> str:
    return hashlib.sha256(canonical_json(output).encode("utf-8")).hexdigest()


def _sign(secret: str, body: dict) -> str:
    msg = (QUOTE_DOMAIN + "|" + canonical_json(body)).encode("utf-8")
    return schnorr_sign(secret, msg)


def _verify(pub: str, body: dict, signature: str) -> bool:
    msg = (QUOTE_DOMAIN + "|" + canonical_json(body)).encode("utf-8")
    return schnorr_verify(pub, msg, signature)


def _sign_receipt(secret: str, body: dict) -> str:
    msg = (RECEIPT_DOMAIN + "|" + canonical_json(body)).encode("utf-8")
    return schnorr_sign(secret, msg)


def _verify_receipt(pub: str, body: dict, signature: str) -> bool:
    msg = (RECEIPT_DOMAIN + "|" + canonical_json(body)).encode("utf-8")
    return schnorr_verify(pub, msg, signature)


def _restrict_to_owner(path: str) -> None:
    """Best-effort ``chmod 600`` on a secret file.

    Windows exposes no POSIX mode bits (``os.chmod`` there only toggles the
    read-only flag), so a failure is ignored - the key is still never
    echoed anywhere, and on POSIX this is what keeps it owner-only.
    """
    try:
        os.chmod(path, KEY_FILE_MODE)
    except OSError:  # pragma: no cover - unsupported filesystem
        pass


class TeeEnclave:
    """Simulated enclave: holds the attestation key and the model measurement."""

    def __init__(self, model_path: str, key_path: str | None = None,
                 service: str = "spectra") -> None:
        self.model_path = model_path
        self.service = service
        if key_path is None:
            base = os.path.dirname(os.path.abspath(model_path)) or "."
            key_path = os.path.join(base, "tee_attestation.key")
        self.key_path = key_path
        self._sk, self._pk = self._load_key()
        self._measurement = measure_file(model_path)

    # -- identity -----------------------------------------------------------

    def _load_key(self) -> tuple[str, str]:
        try:
            if os.path.isfile(self.key_path):
                with open(self.key_path, encoding="utf-8") as fh:
                    sk, pk = fh.read().split()
                _restrict_to_owner(self.key_path)  # older builds wrote it 0644
                return sk, pk
        except (OSError, ValueError):
            pass  # unreadable key -> mint a fresh enclave identity
        sk, pk = schnorr_keypair()
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.key_path)),
                        exist_ok=True)
            with open(self.key_path, "w", encoding="utf-8") as fh:
                fh.write(f"{sk} {pk}")
            # The signing secret: owner-only, never group/world readable.
            _restrict_to_owner(self.key_path)
        except OSError:  # pragma: no cover - read-only filesystem
            pass
        return sk, pk

    @property
    def pubkey(self) -> str:
        return self._pk

    @property
    def measurement(self) -> str | None:
        return self._measurement

    def remeasure(self) -> str | None:
        """Re-measure the model artifact (call after retraining)."""
        self._measurement = measure_file(self.model_path)
        return self._measurement

    # -- attestation --------------------------------------------------------

    def quote(self, nonce: str | None = None) -> dict:
        """Nonce-bound signed attestation of the current model measurement."""
        if self._measurement is None:
            raise TeeError(f"model artifact missing: {self.model_path}")
        body = {
            "domain": QUOTE_DOMAIN,
            "environment": QUOTE_ENVIRONMENT,
            "measurement": self._measurement,
            "nonce": nonce or uuid.uuid4().hex,
            "ts": round(time.time(), 3),
            "service": self.service,
            "pubkey": self._pk,
        }
        return {**body, "signature": _sign(self._sk, body)}

    def verify(self, quote: dict, *, measurement: str | None = None,
               max_age: float = QUOTE_MAX_AGE_S,
               nonce: str | None = None) -> dict:
        """Verify a quote: signature, provenance, freshness, measurement."""
        checks: list[dict] = []

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})

        required = ("domain", "environment", "measurement", "nonce", "ts",
                    "service", "pubkey", "signature")
        missing = [k for k in required if k not in quote]
        check("structure", not missing,
              "all quote fields present" if not missing
              else f"missing {missing}")
        if missing:
            return {"ok": False, "checks": checks,
                    "reason": "malformed quote"}

        body = {k: quote[k] for k in required if k != "signature"}
        check("domain", body.get("domain") == QUOTE_DOMAIN,
              "quote carries the spectra quote domain")
        check("environment", body.get("environment") == QUOTE_ENVIRONMENT,
              f"quote labels itself {QUOTE_ENVIRONMENT} - software "
              "attestation, never hardware-backed")
        sig_ok = _verify(str(quote["pubkey"]), body, str(quote["signature"]))
        check("signature", sig_ok, "issuer Schnorr signature over the quote")
        check("provenance", quote["pubkey"] == self._pk,
              "quote signed by this enclave's key")

        try:
            age = abs(time.time() - float(quote["ts"]))
        except (TypeError, ValueError):
            age = float("inf")
        check("freshness", age <= max_age,
              f"age {age:.1f}s within {max_age:.0f}s")

        expected = measurement if measurement is not None else self._measurement
        if expected is None:
            check("measurement", False, "no local model artifact to compare")
        else:
            check("measurement", quote["measurement"] == expected,
                  "quoted measurement matches the current model artifact")

        nonce_ok = nonce is None or quote["nonce"] == nonce
        check("nonce", nonce_ok, "nonce matches the challenge")

        return {
            "ok": all(c["ok"] for c in checks),
            "checks": checks,
            "environment": quote.get("environment"),
            "measurement": quote["measurement"],
            "expected_measurement": expected,
            "age_s": round(age, 3) if age != float("inf") else None,
        }

    # -- protected inference -------------------------------------------------

    def infer(self, detector, features) -> dict:
        """Score a feature vector inside the 'enclave' and seal a receipt."""
        if self._measurement is None:
            raise TeeError(f"model artifact missing: {self.model_path}")
        try:
            x = np.asarray(features, dtype=np.float64).reshape(-1)
        except (TypeError, ValueError) as exc:
            raise TeeError(
                "only numeric flow metadata enters the enclave") from exc
        if x.shape[0] != N_FEATURES:
            raise TeeError(
                f"expected {N_FEATURES} features, got {x.shape[0]} - "
                "only flow metadata enters the enclave")
        if not np.all(np.isfinite(x)):
            raise TeeError("feature vector contains non-finite values")
        if not getattr(detector, "is_trained", False):
            raise TeeError("model not trained - nothing to attest")

        # one inference pass for score + verdict; detector-like objects that
        # only expose the pair (test doubles, foreign models) keep working
        if hasattr(detector, "score_and_predict"):
            scores, flags = detector.score_and_predict(x)
        else:
            scores, flags = detector.score(x), detector.predict(x)
        score = float(scores[0])
        flagged = bool(flags[0])
        output = {"score": round(score, 2), "flagged": flagged}

        in_digest = digest_features(x.tolist())
        out_digest = digest_output(output)
        body = {
            "domain": RECEIPT_DOMAIN,
            "measurement": self._measurement,
            "input_digest": in_digest,
            "output_digest": out_digest,
            "ts": round(time.time(), 3),
            "pubkey": self._pk,
        }
        receipt = {**body, "signature": _sign_receipt(self._sk, body)}
        return {
            "score": round(score, 2),
            "flagged": flagged,
            "receipt": receipt,
            "claims": {
                "payload_bytes": 0,
                "features_only": True,
                "model_measurement": self._measurement,
            },
        }

    def verify_receipt(self, receipt: dict, features, output: dict) -> dict:
        """Replay a sealed inference: digests + signature + measurement."""
        checks: list[dict] = []

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})

        body = {k: receipt.get(k) for k in
                ("domain", "measurement", "input_digest", "output_digest",
                 "ts", "pubkey")}
        sig_ok = (receipt.get("signature") is not None
                  and _verify_receipt(str(receipt.get("pubkey")), body,
                                      str(receipt["signature"])))
        check("signature", sig_ok, "enclave signature over the receipt")
        check("input_digest",
              receipt.get("input_digest") == digest_features(features),
              "recomputed input digest matches the sealed one")
        check("output_digest",
              receipt.get("output_digest") == digest_output(output),
              "recomputed output digest matches the sealed one")
        check("measurement", receipt.get("measurement") == self._measurement,
              "receipt binds the current model artifact")
        return {"ok": all(c["ok"] for c in checks), "checks": checks}
