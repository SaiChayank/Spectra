"""Host triage v0: evidence grouped by internal source host, plus verdicts.

This is an AGGREGATION of evidence that already exists, not fusion (plan E4,
not built).  Every detector path (anomaly model, C2 beaconing, intel hits)
ends as a row in ``alerts``; this groups those rows by the internal source
host.  ``confidence`` is NOT a calibrated probability: it is the highest
per-alert strength, where strength = max(classifier confidence 0-1, anomaly
percentile / 100), clamped to 0-1.  Monotone in those scores; nothing more.

"Internal" = inside ``config.beaconing_internal_nets`` (RFC1918 + ULA by
default).  There is no ATT&CK mapping in the codebase, so ``technique`` is
always null.  Verdicts (true/expected/false) are stored append-only, latest
wins, and do NOT suppress anything yet (plan E6).  Metadata only.
"""

from __future__ import annotations

import ipaddress

from ..config import Config
from ..store import StoreUnavailable
from .threat_alerts import ThreatAlertService, _split

VERDICTS = ("true", "expected", "false")

#: Newest alerts scanned per request (ponytail: raise or move to SQL GROUP BY
#: if a site has more than _SCAN_PAGES * _PAGE alerts in the window).
_SCAN_PAGES = 10
_PAGE = 500


class HostNotFound(Exception):
    """No evidence for this host (404)."""


class HostTriageService:
    def __init__(self, alerts: ThreatAlertService, store, config: Config):
        self.alerts = alerts
        self.store = store
        self._nets = [ipaddress.ip_network(n, strict=False)
                      for n in config.beaconing_internal_nets]

    def _internal(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self._nets)

    @staticmethod
    def _item(a: dict) -> dict:
        """One alert as an evidence item (no payload, no free text)."""
        strength = max(float(a.get("confidence") or 0.0),
                       float(a.get("anomaly_score") or 0.0) / 100.0)
        return {
            "detector": ("beaconing" if a["threat_type"] == "C2_BEACONING"
                         else "anomaly_model"),
            "threat_type": a["threat_type"],
            "technique": None,
            "first_seen": a["first_seen"],
            "time": a["last_seen"],
            "destination": a["destination"],
            "strength": round(min(1.0, max(0.0, strength)), 3),
            "occurrences": a["occurrences"],
            "alert_id": a["alert_id"],
            "flow_ids": [a["flow_id"]] if a.get("flow_id") is not None else [],
        }

    def _scan(self, **filters) -> list[dict]:
        out: list[dict] = []
        for page in range(_SCAN_PAGES):
            res = self.alerts.list(limit=_PAGE, offset=page * _PAGE, **filters)
            out.extend(res["items"])
            if len(res["items"]) < _PAGE:
                break
        return out

    def _verdicts(self) -> dict[str, dict]:
        return self.store.latest_host_verdicts() if self.store else {}

    @staticmethod
    def _public_verdict(row: dict | None) -> dict | None:
        if row is None:
            return None
        return {"verdict": row["verdict"], "note": row["note"],
                "actor": row["actor"], "created_at": row["created_at"]}

    def list(self, sort: str = "risk", limit: int = 50, offset: int = 0,
             since: float | None = None) -> dict:
        by_host: dict[str, list[dict]] = {}
        for a in self._scan(since=since):
            host, _ = _split(a["source"])
            if self._internal(host):
                by_host.setdefault(host, []).append(self._item(a))
        hosts = []
        for host, items in by_host.items():
            top = max(items, key=lambda i: (i["strength"], i["time"]))
            hosts.append({
                "host": host,
                "confidence": top["strength"],
                "evidence_count": len(items),
                "top_evidence": {k: top[k] for k in
                                 ("detector", "technique", "destination",
                                  "strength")},
                "first_seen": min(i["first_seen"] for i in items),
                "last_seen": max(i["time"] for i in items),
            })
        hosts.sort(key=lambda h: (-h["confidence"], -h["evidence_count"],
                                  -h["last_seen"], h["host"]))
        verdicts = self._verdicts()
        for rank, h in enumerate(hosts, 1):  # rank is always the risk rank
            h["rank"] = rank
            h["verdict"] = self._public_verdict(verdicts.get(h["host"]))
        if sort == "last_seen":
            hosts.sort(key=lambda h: (-h["last_seen"], h["host"]))
        return {"count": len(hosts), "offset": offset,
                "items": hosts[offset:offset + limit]}

    def evidence(self, host: str) -> dict:
        """``host`` must already be a normalised IP string."""
        if not self._internal(host):
            raise HostNotFound(host)
        items = [self._item(a) for a in self._scan(source=host)
                 if _split(a["source"])[0] == host]
        if not items:
            raise HostNotFound(host)
        items.sort(key=lambda i: (i["time"], i["alert_id"]), reverse=True)
        return {"host": host, "count": len(items), "items": items,
                "verdict": self._public_verdict(self._verdicts().get(host))}

    def set_verdict(self, host: str, verdict: str, note: str | None,
                    actor: str) -> dict:
        self.evidence(host)  # 404 unless the host has evidence
        if self.store is None:
            raise StoreUnavailable("persistence is disabled")
        row = self.store.add_host_verdict(host, verdict, note, actor)
        return {"host": host, **self._public_verdict(row)}
