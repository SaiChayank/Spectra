"""Global search classification: pure rules deciding what a query *is*.

One search box serves every SOC entity: an IP endpoint, a domain/SNI, a
numeric id (incident or capture), an analyst-alert id, a TLS fingerprint
(JA3/JA4), a model artifact name - or plain free text.  The classifier
:class:`classify` returns the *kinds* a query matches so the investigation
service only runs the queries that can hit, keeping ``GET /api/search``
bounded regardless of input.

Deliberate properties (tested directly, no I/O anywhere):

* Detection is generous, never exclusive: ``10.0.0.1`` is an ``ip`` (and is
  **not** additionally a ``domain``), a 32-hex string is a ``ja3``, digits
  are a ``number``.  A query with no other match is always ``text``, so
  free text degrades to broad LIKE searches instead of finding nothing.
* Port suffixes are understood: ``10.0.0.1:443`` classifies as the IP
  ``10.0.0.1``; a bracketed IPv6 endpoint is accepted too.
* Everything is bounded by ``MAX_QUERY`` before it reaches SQL.
"""

from __future__ import annotations

import ipaddress
import re

#: Longest accepted query (the router validates first; this guards services).
MAX_QUERY = 255

# kind names (the response echoes them so clients can explain the interpretation)
IP = "ip"
DOMAIN = "domain"
NUMBER = "number"
ALERT_ID = "alert_id"
JA3 = "ja3"
JA4 = "ja4"
MODEL_ID = "model_id"
TEXT = "text"

#: ``alrt_<hex>`` - the alert id minted by spectra.services.threat_alerts.
_ALERT_ID = re.compile(r"^alrt_[0-9a-fA-F]{4,}$")
#: JA3 is an MD5 hex digest of the ClientHello.
_JA3 = re.compile(r"^[0-9a-fA-F]{32}$")
#: JA4: ``<proto+ciphers+exts+alpn>_<sni-hex>_<cipher-hex>`` - three groups,
#: the last two hex (12 chars in short form, 32 when MD5-hashed), first is
#: compact alnum like ``t13d1516h2``.
_JA4 = re.compile(r"^[0-9a-zA-Z]{2,12}_[0-9a-fA-F]{8,32}_[0-9a-fA-F]{8,64}$")
#: Model artifact basenames as the pipeline reports them (model_path base).
_MODEL_ID = re.compile(r"^[0-9A-Za-z._-]+\.(joblib|onnx|pkl|pt)$")
#: One hostname label: alnum + hyphen (no leading/trailing hyphen).
_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def ip_host(value: str) -> str | None:
    """The IP literal inside ``value`` (port stripped), or None if not an IP.

    A numeric trailing group is tried as a port *first* (``fe80::1:443`` is
    an endpoint, not an address), then the raw value - so a bare IPv6
    address whose last hextet is numeric still classifies as an IP.
    """
    host, sep, port = value.rpartition(":")
    candidates = [host] if sep and host and port.isdigit() else []
    candidates.append(value)
    # bracketed IPv6 endpoint: "[fe80::1]:443"
    if value.startswith("[") and "]" in value:
        candidates.append(value[1:value.index("]")])
    for cand in candidates:
        try:
            ipaddress.ip_address(cand)
        except ValueError:
            continue
        return cand
    return None


def looks_like_domain(value: str) -> bool:
    """Dotted hostname shape (also matches SNI), excluding IPs and blanks."""
    if not value or len(value) > MAX_QUERY:
        return False
    if " " in value or "." not in value or value.startswith("."):
        return False
    labels = value.rstrip(".").split(".")
    if len(labels) < 2 or not all(labels):
        return False
    if any(len(label) > 63 or not _LABEL.match(label) for label in labels):
        return False
    # The TLD carries at least one letter: ``1.2.3``/``10.0.0.1`` are version
    # numbers and addresses, not hostnames (IPs also never reach this call
    # from classify, which checks ip_host first).
    return any(char.isalpha() for char in labels[-1])


def classify(query: str) -> list[str]:
    """Ordered, de-duplicated kinds for one query (``[]`` when empty).

    Order is stable (ip, alert_id, ja3, ja4, number, model_id, domain,
    text) so responses are deterministic for tests and clients.
    """
    q = (query or "").strip()[:MAX_QUERY]
    if not q:
        return []
    kinds: list[str] = []
    is_ip = ip_host(q) is not None
    if is_ip:
        kinds.append(IP)
    if _ALERT_ID.match(q):
        kinds.append(ALERT_ID)
    if _JA3.match(q):
        kinds.append(JA3)
    if _JA4.match(q):
        kinds.append(JA4)
    if q.isdigit():
        kinds.append(NUMBER)
    if _MODEL_ID.match(q):
        kinds.append(MODEL_ID)
    # A dotted IP already matched as ip; never also pretend to be a domain
    # (the version-number case "1.2.3" has a non-hostname final label and
    # is rejected by looks_like_domain anyway).
    if not is_ip and looks_like_domain(q):
        kinds.append(DOMAIN)
    if not kinds:
        kinds.append(TEXT)
    return kinds


__all__ = [
    "MAX_QUERY", "IP", "DOMAIN", "NUMBER", "ALERT_ID", "JA3", "JA4",
    "MODEL_ID", "TEXT", "classify", "looks_like_domain", "ip_host",
]
