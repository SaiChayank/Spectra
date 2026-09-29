"""TLS algorithm registry with post-quantum risk classification.

Sources (verified against IANA/IESG publications):
  * TLS Supported Groups: IANA tls-parameters registry (RFC 10024, 8446, 7919,
    draft-ietf-tls-mlkem)
  * SignatureScheme: IANA tls-parameters (RFC 8446, draft-ietf-tls-mldsa-06)
  * Cipher suites: IANA tls-parameters (RFC 5246, 8446)

Classification vocabulary:
  scheme:   "rsa_transport" | "dhe" | "ecdhe" | "tls13" | "psk" | "unknown"
  kx_class: "classical" | "hybrid" | "pqc" | "unknown"
  quantum:  "vulnerable" | "resistant" | "unknown"
"""

from __future__ import annotations

# --- named groups (supported_groups / key_share) ---------------------------

GROUPS: dict[int, dict] = {
    # elliptic curves: classically secure, broken by a cryptographically
    # relevant quantum computer (Shor).
    0x0017: {"name": "secp256r1", "kx_class": "classical", "quantum": "vulnerable"},
    0x0018: {"name": "secp384r1", "kx_class": "classical", "quantum": "vulnerable"},
    0x0019: {"name": "secp521r1", "kx_class": "classical", "quantum": "vulnerable"},
    0x001D: {"name": "x25519", "kx_class": "classical", "quantum": "vulnerable"},
    0x001E: {"name": "x448", "kx_class": "classical", "quantum": "vulnerable"},
    # finite-field DH: also vulnerable (and deprecated for new deployments)
    0x0100: {"name": "ffdhe2048", "kx_class": "classical", "quantum": "vulnerable"},
    0x0101: {"name": "ffdhe3072", "kx_class": "classical", "quantum": "vulnerable"},
    0x0102: {"name": "ffdhe4096", "kx_class": "classical", "quantum": "vulnerable"},
    0x0103: {"name": "ffdhe6144", "kx_class": "classical", "quantum": "vulnerable"},
    0x0104: {"name": "ffdhe8192", "kx_class": "classical", "quantum": "vulnerable"},
    # pure post-quantum KEM (NIST FIPS 203)
    0x0201: {"name": "MLKEM768", "kx_class": "pqc", "quantum": "resistant"},
    # standardised hybrids (RFC 10024)
    0x11EB: {"name": "SecP256r1MLKEM768", "kx_class": "hybrid", "quantum": "resistant"},
    0x11EC: {"name": "X25519MLKEM768", "kx_class": "hybrid", "quantum": "resistant"},
    0x11ED: {"name": "SecP384r1MLKEM1024", "kx_class": "hybrid", "quantum": "resistant"},
    0x11EE: {"name": "curveSM2MLKEM768", "kx_class": "hybrid", "quantum": "resistant"},
    # pre-standard Kyber hybrids (observed in the wild; IANA: obsolete)
    0x6399: {"name": "X25519Kyber768Draft00", "kx_class": "hybrid",
             "quantum": "resistant", "obsolete": True},
    0x639A: {"name": "SecP256r1Kyber768Draft00", "kx_class": "hybrid",
             "quantum": "resistant", "obsolete": True},
}

# --- cipher suites ----------------------------------------------------------

TLS13_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

CIPHER_SUITES: dict[int, dict] = {
    # TLS 1.3: key exchange is group-based, suite only picks AEAD/MAC
    **{code: {"name": name, "scheme": "tls13", "auth": "tls13",
              "deprecated": False, "aead": True}
       for code, name in TLS13_SUITES.items()},
    # RSA key transport - no forward secrecy, harvestable, widely deprecated
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": True},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": True},
    0x003C: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA256", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": False},
    0x003D: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA256", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": False},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": False, "aead": True},
    0x009D: {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": False, "aead": True},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": True},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": True},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "scheme": "rsa_transport",
             "auth": "rsa", "deprecated": True},
    # ephemeral finite-field DH (forward secrecy, still classically breakable)
    0x0033: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "scheme": "dhe",
             "auth": "rsa", "deprecated": False},
    0x0039: {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "scheme": "dhe",
             "auth": "rsa", "deprecated": False},
    0x009E: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "scheme": "dhe",
             "auth": "rsa", "deprecated": False, "aead": True},
    0x009F: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "scheme": "dhe",
             "auth": "rsa", "deprecated": False, "aead": True},
    0x00A2: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "scheme": "dhe",
             "auth": "rsa", "deprecated": False},
    0x00A3: {"name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "scheme": "dhe",
             "auth": "rsa", "deprecated": False},
    # ephemeral ECDH
    0xC013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False},
    0xC014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False},
    0xC027: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False},
    0xC02B: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "scheme": "ecdhe",
             "auth": "ecdsa", "deprecated": False, "aead": True},
    0xC02C: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "scheme": "ecdhe",
             "auth": "ecdsa", "deprecated": False, "aead": True},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False, "aead": True},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False, "aead": True},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "scheme": "ecdhe",
             "auth": "rsa", "deprecated": False, "aead": True},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "scheme": "ecdhe",
             "auth": "ecdsa", "deprecated": False, "aead": True},
}

# --- signature schemes ------------------------------------------------------

SIGNATURE_SCHEMES: dict[int, dict] = {
    0x0401: {"name": "rsa_pkcs1_sha256", "quantum": "vulnerable"},
    0x0501: {"name": "rsa_pkcs1_sha384", "quantum": "vulnerable"},
    0x0601: {"name": "rsa_pkcs1_sha512", "quantum": "vulnerable"},
    0x0403: {"name": "ecdsa_secp256r1_sha256", "quantum": "vulnerable"},
    0x0503: {"name": "ecdsa_secp384r1_sha384", "quantum": "vulnerable"},
    0x0603: {"name": "ecdsa_secp521r1_sha512", "quantum": "vulnerable"},
    0x0804: {"name": "rsa_pss_rsae_sha256", "quantum": "vulnerable"},
    0x0805: {"name": "rsa_pss_rsae_sha384", "quantum": "vulnerable"},
    0x0806: {"name": "rsa_pss_rsae_sha512", "quantum": "vulnerable"},
    0x0807: {"name": "ed25519", "quantum": "vulnerable"},
    0x0808: {"name": "ed448", "quantum": "vulnerable"},
    0x0809: {"name": "rsa_pss_pss_sha256", "quantum": "vulnerable"},
    0x080A: {"name": "rsa_pss_pss_sha384", "quantum": "vulnerable"},
    0x080B: {"name": "rsa_pss_pss_sha512", "quantum": "vulnerable"},
    # ML-DSA (FIPS 204) - draft-ietf-tls-mldsa-06
    0x0904: {"name": "mldsa44", "quantum": "resistant"},
    0x0905: {"name": "mldsa65", "quantum": "resistant"},
    0x0906: {"name": "mldsa87", "quantum": "resistant"},
}

PQ_SIGNATURE_CODES = {c for c, v in SIGNATURE_SCHEMES.items() if v["quantum"] == "resistant"}


# --- lookups ----------------------------------------------------------------


def group_info(code: int | None) -> dict:
    if not code:
        return {"code": 0, "name": "none", "kx_class": "unknown", "quantum": "unknown"}
    info = GROUPS.get(code)
    if info:
        return {"code": code, **info}
    return {"code": code, "name": f"unknown(0x{code:04x})", "kx_class": "unknown",
            "quantum": "unknown"}


def cipher_info(code: int | None) -> dict:
    if not code:
        return {"code": 0, "name": "none", "scheme": "unknown", "auth": "unknown",
                "deprecated": False}
    info = CIPHER_SUITES.get(code)
    if info:
        return {"code": code, **info}
    return {"code": code, "name": f"unknown(0x{code:04x})", "scheme": "unknown",
            "auth": "unknown", "deprecated": False}


def signature_info(code: int) -> dict:
    info = SIGNATURE_SCHEMES.get(code)
    if info:
        return {"code": code, **info}
    return {"code": code, "name": f"unknown(0x{code:04x})", "quantum": "unknown"}


def best_group(candidates: list[int]) -> int:
    """Pick the most quantum-resistant group from a list of offered codes."""
    rank = {"pqc": 3, "hybrid": 2, "classical": 1, "unknown": 0}
    best, best_rank = 0, -1
    for code in candidates:
        r = rank.get(group_info(code)["kx_class"], 0)
        if r > best_rank:
            best, best_rank = code, r
    return best
