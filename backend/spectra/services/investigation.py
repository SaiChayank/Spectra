"""Investigation read-side: one bundle per incident + global entity search.

The SOC investigation experience needs everything about an incident in a
single, bounded response: the incident row with notes/timeline, its member
alerts, the flows those alerts and the incident's detection point at, TLS/
QUIC metadata and module annotations over those flows, related hosts and
domains, the slice of the correlation graph (and digital-twin context) the
incident touches, audit references, model lineage - and a search box that
resolves any identifier an analyst pastes in.

Design rules (mirroring IncidentService):

* Read-only: this service never writes, never raises into the pipeline.
* No service imports another service.  The correlation graph and the model
  identity arrive as injected providers, exactly like IncidentService's
  ``graph_provider``; everything else goes through the store facade.
* **Everything is bounded.**  The related-flow page, the aggregate window
  (``config.investigation_evidence_rows``), graph nodes/edges, annotations,
  audit references and each search section all have hard caps, so no bundle
  or search response grows with the database.

Search interpretation lives in :mod:`spectra.entity_search` (pure); this
service only maps classified kinds onto bounded store queries.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter
from typing import Callable

from ..capabilities import SCORING_POLICY, capability_contracts
from ..entity_search import (
    DOMAIN,
    IP,
    JA3,
    JA4,
    MAX_QUERY,
    MODEL_ID,
    NUMBER,
    TEXT,
    ALERT_ID,
    classify,
    ip_host,
    looks_like_domain,
)
from ..incident_correlation import endpoint_nodes
from ..store import Store

log = logging.getLogger("spectra.engine")

# -- bounds (see also config.investigation_* / search_section_limit) ----------

_MAX_FLOW_LIMIT = 500        # related flows per bundle page
_MAX_EVIDENCE_ROWS = 2000    # aggregate window (rows hydrated per bundle)
_MAX_SEARCH_LIMIT = 50       # per section in one search response
_MAX_HOSTS = 50              # anchor hosts/SNIs fed into the SQL
_MAX_SNIS = 50
_MAX_FLOW_IDS = 200          # = _MAX_ALERTS_PER_INCIDENT + detection flow
_MAX_SECTION_ROWS = 50       # hosts/domains listings
_MAX_ANNOTATIONS = 20        # per annotation kind
_MAX_JA_ENTRIES = 10         # distinct JA3/JA4 fingerprints summarised
_MAX_FLOW_REASONS = 20
_MAX_AUDIT_SCAN = 500        # audit rows scanned per prefix
_MAX_AUDIT_ITEMS = 100
_MAX_GRAPH_NODES = 100
_MAX_GRAPH_EDGES = 200
_MAX_MODULE_EVENTS = 50      # robustness observations per kind + window

#: Robustness event kinds the adversarial module emits (persisted by the
#: engine's event hook); counted as contributing context per investigation.
_ROBUSTNESS_EVENT_KINDS = ("evasion", "drift")

_SECTIONS = ("incidents", "alerts", "flows", "captures",
             "hosts", "domains", "models")


class InvestigationError(Exception):
    """Mapped to an HTTP error by the investigation router."""

    status_code = 400
    default_detail = "investigation error"

    def __init__(self, detail: str | None = None):
        self.detail = self.default_detail if detail is None else detail
        super().__init__(self.detail)


class InvestigationUnavailable(InvestigationError):
    status_code = 503
    default_detail = "investigation requires persistence to be enabled"


class InvestigationNotFound(InvestigationError):
    status_code = 404
    default_detail = "incident not found"


class InvestigationValidationError(InvestigationError):
    status_code = 400
    default_detail = "invalid investigation request"


class InvestigationService:
    """Bundle one incident with all its evidence; search every key entity."""

    def __init__(self, store: Store | None, config=None, *,
                 graph_provider: Callable[[], object] | None = None,
                 model_info: Callable[[], dict] | None = None,
                 capability_provider: Callable[[], dict] | None = None) -> None:
        self.store = store
        self.config = config
        #: Callable returning the live CorrelationGraph (or None) - injected
        #: by the pipeline so this service never imports the correlation
        #: service (same seam as IncidentService.graph_provider).
        self._graph_provider = graph_provider
        #: Current scoring-model identity (id/version), guarded on call.
        self._model_info = model_info
        #: Live per-module capability status (SpectraEngine.capability_
        #: status), guarded on call; absent in pure/offline constructions
        #: where ``available`` stays None ("not probed").
        self._capability_provider = capability_provider

    # -- reads: the bundle ----------------------------------------------------

    def bundle(self, incident_id: int, *, flow_limit: int | None = None,
               flow_offset: int = 0) -> dict:
        """Everything an analyst needs about one incident, all bounded."""
        store = self._require_store()
        incident = store.get_incident(int(incident_id))
        if incident is None:
            raise InvestigationNotFound()

        alerts = store.get_incident_alerts(incident["id"])
        notes = store.incident_notes(incident["id"])
        anchors, window = self._anchors(incident, alerts)

        limit = int(flow_limit or self._cfg("investigation_flow_limit", 100))
        limit = min(max(1, limit), _MAX_FLOW_LIMIT)
        offset = max(0, int(flow_offset))
        flows = store.related_flows(**anchors, limit=limit, offset=offset)

        evidence_cap = int(self._cfg("investigation_evidence_rows", 500))
        evidence_cap = min(max(1, evidence_cap), _MAX_EVIDENCE_ROWS)
        window_rows = store.related_flows(**anchors, limit=evidence_cap,
                                          offset=0)["items"]

        graph = self._graph()
        graph_section = self._graph_section(incident, alerts, anchors, graph)
        annotations = _annotations(window_rows, alerts)
        twin_section = self._twin(graph, graph_section)
        audit_section = self._audit_refs(incident, alerts)

        return {
            "incident": incident,
            "notes": notes,
            "note_count": len(notes),
            "timeline": store.incident_events(incident["id"]),
            "alerts": {"count": len(alerts), "items": alerts},
            "flows": flows,
            "window": {"since": window[0], "until": window[1],
                       "evidence_rows": len(window_rows),
                       "evidence_total": flows["count"]},
            "tls": self._tls_summary(window_rows, flows["count"]),
            "evidence": self._evidence(incident, alerts, window_rows),
            "hosts": _related_hosts(window_rows)[:_MAX_SECTION_ROWS],
            "domains": _related_domains(window_rows)[:_MAX_SECTION_ROWS],
            "annotations": annotations,
            "graph": graph_section,
            "twin": twin_section,
            "audit": audit_section,
            "models": self._models(incident, alerts),
            "modules": self._module_status(window, annotations, graph_section,
                                           twin_section, audit_section),
            "generated_at": time.time(),
        }

    def search(self, query: str, *, limit: int | None = None) -> dict:
        """Global search over incidents, alerts, flows, captures, graph, models."""
        store = self._require_store()
        q = (query or "").strip()[:MAX_QUERY]
        if not q:
            raise InvestigationValidationError("query must not be empty")
        kinds = classify(q)
        wanted = set(kinds)
        cap = int(limit or self._cfg("search_section_limit", 10))
        cap = min(max(1, cap), _MAX_SEARCH_LIMIT)

        results = {name: {"count": 0, "items": []} for name in _SECTIONS}
        exact_id = int(q) if NUMBER in wanted else None

        # -- incidents (id, affected entities, title/threat class) ------------
        if wanted & {IP, DOMAIN, TEXT, NUMBER}:
            results["incidents"] = store.search_incidents(
                q, cap, exact_id=exact_id, entity=True,
                title=bool(wanted & {DOMAIN, TEXT}),
            )

        # -- alerts (id, endpoints, metadata text, model identity) ------------
        if wanted & {ALERT_ID, IP, DOMAIN, JA3, JA4, MODEL_ID, TEXT}:
            results["alerts"] = store.search_alerts(
                q, cap,
                alert_id=ALERT_ID in wanted,
                endpoint=IP in wanted,
                text=bool(wanted & {DOMAIN, JA3, JA4, TEXT}),
                model=MODEL_ID in wanted,
            )

        # -- flows (endpoints, SNI, TLS fingerprints) -------------------------
        if wanted & {IP, DOMAIN, JA3, JA4, TEXT}:
            results["flows"] = store.search_flows(
                q, cap,
                endpoint=IP in wanted,
                sni=bool(wanted & {DOMAIN, TEXT}),
                fingerprint=bool(wanted & {JA3, JA4}),
            )

        # -- captures (numeric id) --------------------------------------------
        if NUMBER in wanted and exact_id is not None:
            capture = store.get_capture(exact_id)
            if capture is not None:
                results["captures"] = {"count": 1, "items": [capture]}

        # -- correlation graph (host/domain nodes) ----------------------------
        if wanted & {IP, DOMAIN, TEXT}:
            self._search_nodes(q, results["hosts"], results["domains"], cap)

        # -- model identities ---------------------------------------------------
        if wanted & {MODEL_ID, TEXT}:
            info = self._current_model()
            items = []
            if info and (q.lower() in str(info.get("id") or "").lower()
                         or q.lower() in str(info.get("version") or "").lower()):
                items.append({"id": info.get("id"),
                              "version": info.get("version"),
                              "current": True})
            items.extend({**row, "current": False}
                         for row in store.alert_models(q, cap))
            items = items[:cap]
            results["models"] = {"count": len(items), "items": items}

        total = sum(section["count"] for section in results.values())
        return {"query": q, "kinds": kinds, "count": total,
                "limit": cap, "results": results}

    # -- bundle internals -------------------------------------------------------

    def _require_store(self) -> Store:
        if self.store is None:
            raise InvestigationUnavailable()
        return self.store

    def _cfg(self, name: str, default):
        return getattr(self.config, name, default) if self.config else default

    def _graph(self):
        if self._graph_provider is None:
            return None
        try:
            return self._graph_provider()
        except Exception as exc:  # noqa: BLE001 - a graph failure never 500s a bundle
            log.warning("investigation graph provider failed: %s", exc)
            return None

    def _anchors(self, incident: dict, alerts: list[dict]) -> tuple[dict, tuple]:
        """Bounded related-activity anchors: direct ids, hosts, SNIs, window.

        Window = the incident's sighting interval widened by
        ``config.incident_window_seconds`` (the correlation window), so
        "related flows" means the activity around the incident, not the
        whole table.  Collections are capped - the SQL stays bounded.
        """
        window = float(self._cfg("incident_window_seconds", 1800.0))
        created = float(incident.get("created_at") or 0.0)
        first = incident.get("first_seen")
        last = incident.get("last_seen")
        since = (float(first) if first else created) - window
        until = (float(last) if last else created) + window

        hosts: list[str] = []
        snis: list[str] = []
        flow_ids: list[int] = []
        alert_ids: list[str] = []
        seen_hosts: set[str] = set()
        seen_snis: set[str] = set()
        seen_ids: set[int] = set()
        seen_alerts: set[str] = set()

        def add_host(value: str) -> None:
            host = ip_host(value) or ("" if looks_like_domain(value) else value)
            if host and host not in seen_hosts and len(seen_hosts) < _MAX_HOSTS:
                seen_hosts.add(host)
                hosts.append(host)

        def add_sni(value: str) -> None:
            sni = str(value).strip().rstrip(".")
            if sni and sni not in seen_snis and len(seen_snis) < _MAX_SNIS:
                seen_snis.add(sni)
                snis.append(sni)

        def add_flow_id(value) -> None:
            try:
                fid = int(value)
            except (TypeError, ValueError):
                return
            if fid > 0 and fid not in seen_ids and len(seen_ids) < _MAX_FLOW_IDS:
                seen_ids.add(fid)
                flow_ids.append(fid)

        def add_alert_id(value) -> None:
            text = str(value or "")
            if text and text not in seen_alerts \
                    and len(seen_alerts) < _MAX_FLOW_IDS:
                seen_alerts.add(text)
                alert_ids.append(text)

        for entity in incident.get("affected_entities") or []:
            text = str(entity)
            if looks_like_domain(text) and ip_host(text) is None:
                add_sni(text)
            else:
                add_host(text)
        for alert in alerts:
            add_host(str(alert.get("source") or ""))
            add_host(str(alert.get("destination") or ""))
            sni = (alert.get("metadata") or {}).get("sni")
            if sni:
                add_sni(str(sni))
            add_flow_id(alert.get("flow_id"))
            add_alert_id(alert.get("alert_id"))
        add_flow_id(incident.get("detection_id"))
        detection_id = incident.get("detection_id")
        if detection_id and len(seen_hosts) < _MAX_HOSTS:
            # A detection-only incident has no alerts to anchor endpoints on.
            flow = self.store.get_flow(int(detection_id)) if self.store else None
            if flow:
                add_host(str(flow.get("src") or ""))
                add_host(str(flow.get("dst") or ""))
                if flow.get("sni"):
                    add_sni(str(flow["sni"]))

        return ({"flow_ids": flow_ids, "alert_ids": alert_ids, "hosts": hosts,
                 "snis": snis, "since": since, "until": until},
                (since, until))

    def _graph_section(self, incident: dict, alerts: list[dict],
                       anchors: dict, graph) -> dict:
        """The incident's slice of the correlation graph (nodes + edges)."""
        if graph is None:
            return {"available": False, "nodes": [], "edges": [], "missing": []}
        want: list[str] = []
        seen: set[str] = set()

        def add(nid: str) -> None:
            if nid and nid not in seen and len(seen) < _MAX_GRAPH_NODES * 2:
                seen.add(nid)
                want.append(nid)

        for nid in incident.get("related_graph_nodes") or []:
            add(str(nid))
        for alert in alerts:
            for nid in endpoint_nodes(alert):
                add(nid)
        for host in anchors.get("hosts") or ():
            add(f"host:{host}")
            add(f"ip:{host}")
        for sni in anchors.get("snis") or ():
            add(f"domain:{sni}")

        present, missing = [], []
        for nid in want:
            try:
                node = graph.node(nid)
            except Exception:  # noqa: BLE001 - graph reads never fail a bundle
                node = None
            if node is None:
                if len(missing) < 20:
                    missing.append(nid)
            elif len(present) < _MAX_GRAPH_NODES:
                present.append(node)
        present_ids = {node["id"] for node in present}

        # One-hop neighbours make the slice renderable without dangling ids.
        neighbour_ids: list[str] = []
        for src, nbrs in graph.edges.items():
            if len(present_ids) + len(neighbour_ids) >= _MAX_GRAPH_NODES:
                break
            for dst in nbrs:
                if src in present_ids and dst not in present_ids \
                        and dst not in neighbour_ids:
                    neighbour_ids.append(dst)
                if dst in present_ids and src not in present_ids \
                        and src not in neighbour_ids:
                    neighbour_ids.append(src)
        budget = max(0, _MAX_GRAPH_NODES - len(present))
        for nid in neighbour_ids[:budget]:
            try:
                node = graph.node(nid)
            except Exception:  # noqa: BLE001 - graph reads never fail a bundle
                node = None
            if node is not None:
                present.append(node)
        wanted_ids = {node["id"] for node in present}

        edges: list[dict] = []
        truncated = False
        for src, nbrs in graph.edges.items():
            for dst, weights in nbrs.items():
                if src not in wanted_ids or dst not in wanted_ids:
                    continue
                for etype, weight in weights.items():
                    edges.append({"source": src, "target": dst, "type": etype,
                                  "weight": round(float(weight), 2)})
                    if len(edges) >= _MAX_GRAPH_EDGES:
                        truncated = True
                        break
                if truncated:
                    break
            if truncated:
                break
        return {"available": True, "nodes": present, "edges": edges,
                "missing": missing, "truncated": truncated}

    def _twin(self, graph, graph_section: dict) -> dict:
        """Digital-twin context for the graph slice (zone, criticality)."""
        if graph is None or not graph_section.get("available"):
            return {"available": False}
        try:
            from ..modules.twin.topology import build_topology
            topology = build_topology(graph)
        except Exception as exc:  # noqa: BLE001 - twin context is optional
            log.warning("investigation twin topology failed: %s", exc)
            return {"available": False, "error": str(exc)}
        keep = {node["id"] for node in graph_section["nodes"]}
        nodes = [n for n in topology["nodes"] if n["id"] in keep]
        if not nodes:
            return {"available": False}
        assets = {n["id"] for n in nodes if n["asset"]}
        zones = [z for z in topology["zones"] if assets & set(z["assets"])]
        edges = [e for e in topology["asset_edges"]
                 if e["source"] in keep and e["target"] in keep]
        return {"available": True, "nodes": nodes, "zones": zones,
                "asset_edges": edges,
                "summary": {"nodes": len(nodes),
                            "assets": len(assets),
                            "zones": len(zones),
                            "edges": len(edges)}}

    def _audit_refs(self, incident: dict, alerts: list[dict]) -> dict:
        """Audit-log references for this incident (bounded scan).

        ``incident.*`` entries can only exist at/after creation, so the scan
        starts at ``created_at`` and filters payload ids in memory; alert
        entries are kept when they name a member alert.  Both scans are
        capped, keeping the bundle response finite.
        """
        if self.store is None:  # pragma: no cover - bundle guards earlier
            return {"count": 0, "items": []}
        created = float(incident.get("created_at") or 0.0)
        member_ids = {str(a.get("alert_id")) for a in alerts}
        matched: list[dict] = []
        scans = (
            ("incident.", lambda payload: payload.get("id") == incident["id"]),
            ("alert.", lambda payload: str(payload.get("alert_id")) in member_ids),
        )
        for prefix, keep in scans:
            rows = self.store.audit_entries(limit=_MAX_AUDIT_SCAN,
                                            kind_prefix=prefix,
                                            since=created or None)
            for row in rows:
                try:
                    payload = json.loads(row.get("payload") or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if isinstance(payload, dict) and keep(payload):
                    matched.append({"seq": int(row["seq"]), "ts": row["ts"],
                                    "kind": row["kind"], "actor": row["actor"],
                                    "payload": payload,
                                    "entry_hash": row["entry_hash"]})
        matched.sort(key=lambda r: -r["seq"])
        return {"count": len(matched),
                "items": matched[:_MAX_AUDIT_ITEMS]}

    def _models(self, incident: dict, alerts: list[dict]) -> dict:
        current = self._current_model()
        return {
            "current": current,
            "versions": list(incident.get("model_versions") or []),
            "alerts": [{"alert_id": a.get("alert_id"),
                        "model_id": a.get("model_id"),
                        "model_version": a.get("model_version")}
                       for a in alerts],
        }

    def _current_model(self) -> dict:
        if self._model_info is None:
            return {}
        try:
            return dict(self._model_info() or {})
        except Exception as exc:  # noqa: BLE001 - model identity is optional
            log.warning("investigation model info failed: %s", exc)
            return {}

    def _capability_status(self) -> dict:
        """Live module availability; an absent/failing probe degrades to
        ``available: None`` ("not probed"), never to an error."""
        if self._capability_provider is None:
            return {}
        try:
            return dict(self._capability_provider() or {})
        except Exception as exc:  # noqa: BLE001 - status is optional
            log.warning("investigation capability probe failed: %s", exc)
            return {}

    def _robustness_observations(self, since: float, until: float) -> int:
        """Evasion/drift events inside the incident window (bounded)."""
        total = 0
        for kind in _ROBUSTNESS_EVENT_KINDS:
            try:
                page = self.store.query_events(type=kind, since=since,
                                               until=until,
                                               limit=_MAX_MODULE_EVENTS)
                total += int(page.get("count", 0))
            except Exception as exc:  # noqa: BLE001 - context is optional
                log.warning("investigation robustness events failed: %s", exc)
        return total

    def _module_status(self, window: tuple, annotations: dict,
                       graph_section: dict, twin_section: dict,
                       audit_section: dict) -> dict:
        """Every advanced module's maturity, live availability and its
        contribution to THIS investigation - the transparent "who added
        what" view.  Contributions are counts of evidence already
        rendered elsewhere in the bundle; nothing here can change a score
        (see capabilities.SCORING_POLICY)."""
        contracts = capability_contracts()
        live = self._capability_status()
        counts = annotations.get("counts") or {}
        robustness = self._robustness_observations(float(window[0]),
                                                   float(window[1]))
        tee_detail = (live.get("tee") or {}).get("detail") or "not probed"
        graph_nodes = len(graph_section.get("nodes") or []) \
            if graph_section.get("available") else 0
        twin_nodes = int((twin_section.get("summary") or {}).get("nodes", 0)) \
            if twin_section.get("available") else 0
        audit_refs = int(audit_section.get("count", 0))

        contributed = {
            "pqc": counts.get("pqc", 0),
            "adversarial": robustness,
            "correlation": graph_nodes,
            "audit": audit_refs,
            "bio": counts.get("bio", 0),
            "tee": 0,
            "federated": 0,
            "twin": 1 if twin_section.get("available") else 0,
            "edge": counts.get("edge", 0),
            "edge_deployment": 0,
        }
        summaries = {
            "pqc": f"{contributed['pqc']} quantum-readiness annotation(s) "
                   f"on this incident's evidence",
            "adversarial": f"{robustness} evasion/drift observation(s) "
                           f"inside the incident window",
            "correlation": (f"{graph_nodes} related graph node(s) in the "
                            f"bundle slice" if graph_nodes
                            else "graph slice unavailable"),
            "audit": f"{audit_refs} audit integrity reference(s) for this "
                     f"incident",
            "bio": f"{contributed['bio']} behavioural annotation(s) "
                   f"(immune/SNN/swarm)",
            "tee": "on-demand simulated attestation status only; no "
                   f"per-alert evidence ({tee_detail})",
            "federated": "on-demand simulated aggregation only; no "
                         "per-alert evidence",
            "twin": (f"simulated blast radius over {twin_nodes} topology "
                     f"node(s)" if twin_nodes
                     else "twin context unavailable"),
            "edge": f"{contributed['edge']} slice tag(s) on flows/alerts",
            "edge_deployment": "simulated deployment registry; not "
                               "incident evidence",
        }

        items = []
        for key, contract in contracts.items():
            probe = live.get(key) or {}
            items.append({
                "key": key,
                "title": contract["title"],
                "status": contract["status"],
                "hardware_backed": contract["hardware_backed"],
                "evidence_only": contract["evidence_only"],
                "affects_alert_scoring": contract["affects_alert_scoring"],
                "available": probe.get("available"),
                "detail": probe.get("detail"),
                "failures": probe.get("failures"),
                "contributed": int(contributed.get(key, 0)),
                "summary": summaries.get(key, ""),
            })
        return {"scoring_policy": SCORING_POLICY, "items": items}

    def _tls_summary(self, rows: list[dict], total: int) -> dict:
        tls: Counter = Counter()
        quic: Counter = Counter()
        alpn: Counter = Counter()
        fingerprints: dict[str, dict] = {}
        for row in rows:
            if row.get("tls_version"):
                tls[str(row["tls_version"])] += 1
            if row.get("quic_version"):
                quic[str(row["quic_version"])] += 1
            value = row.get("alpn")
            if value:
                key = ",".join(str(v) for v in value) \
                    if isinstance(value, (list, tuple)) else str(value)
                alpn[key] += 1
            for column in ("ja3", "ja4"):
                fingerprint = row.get(column)
                if not fingerprint:
                    continue
                entry = fingerprints.setdefault(
                    str(fingerprint),
                    {"value": str(fingerprint), "flows": 0, "snis": set(),
                     "kind": column})
                entry["flows"] += 1
                if row.get("sni"):
                    entry["snis"].add(str(row["sni"]))
        top = sorted(fingerprints.values(),
                     key=lambda e: (-e["flows"], e["value"]))
        rendered = [{"kind": e["kind"], "value": e["value"],
                     "flows": e["flows"], "snis": sorted(e["snis"])}
                    for e in top[:_MAX_JA_ENTRIES]]
        return {
            "tls_versions": dict(tls.most_common()),
            "quic_versions": dict(quic.most_common()),
            "alpn": dict(alpn.most_common()),
            "fingerprints": rendered,
            "sampled": len(rows),
            "flows_total": total,
        }

    def _evidence(self, incident: dict, alerts: list[dict],
                  rows: list[dict]) -> dict:
        """Behavioural evidence: per-alert verdicts + detector reasons."""
        factors: list[str] = []
        seen_factors: set[str] = set()
        for alert in alerts:
            for factor in alert.get("severity_factors") or []:
                text = str(factor)
                if text not in seen_factors:
                    seen_factors.add(text)
                    factors.append(text)
        alert_evidence = [
            {"alert_id": a.get("alert_id"), "threat_type": a.get("threat_type"),
             "severity": a.get("severity"), "confidence": a.get("confidence"),
             "anomaly_score": a.get("anomaly_score"),
             "evidence": a.get("evidence") or {}}
            for a in alerts
        ]
        flow_reasons = [
            {"flow_id": row.get("id"), "score": row.get("score"),
             "reasons": row.get("reasons") or []}
            for row in rows if row.get("anomaly") and row.get("reasons")
        ][:_MAX_FLOW_REASONS]
        return {
            "summary": incident.get("evidence_summary"),
            "primary_threat": incident.get("primary_threat_class"),
            "severity_factors": factors,
            "alerts": alert_evidence,
            "flow_reasons": flow_reasons,
            "sampled": len(rows),
        }

    def _search_nodes(self, q: str, hosts: dict, domains: dict,
                      cap: int) -> None:
        """Classified query -> graph host/domain nodes (in-memory, bounded)."""
        graph = self._graph()
        if graph is None:
            return
        needle = q.lower()
        host_total = domain_total = 0
        for node in list(graph.nodes.values()):
            nid = str(node.get("id") or "")
            label = str(node.get("label") or "")
            if q not in nid and needle not in label.lower():
                continue
            ntype = node.get("type")
            if ntype == "host":
                host_total += 1
                if len(hosts["items"]) < cap:
                    hosts["items"].append(graph.node(nid))
            elif ntype == "domain":
                domain_total += 1
                if len(domains["items"]) < cap:
                    domains["items"].append(graph.node(nid))
        hosts["count"] = host_total
        domains["count"] = domain_total


# -- pure shaping helpers over the bounded flow window ------------------------


def _related_hosts(rows: list[dict]) -> list[dict]:
    """Hosts behind the window's flows: flow/detection counts, roles, span."""
    stats: dict[str, dict] = {}
    for row in rows:
        ts = float(row.get("last_ts") or row.get("ts") or 0.0)
        detection = 1 if row.get("anomaly") else 0
        for column, role in (("src", "src"), ("dst", "dst")):
            host = ip_host(str(row.get(column) or ""))
            if not host:
                continue
            entry = stats.get(host)
            if entry is None:
                entry = stats[host] = {
                    "host": host, "flows": 0, "detections": 0,
                    "roles": set(), "first_ts": None, "last_ts": None}
            if row.get("id") not in entry.setdefault("_rows", set()):
                entry["_rows"].add(row.get("id"))
                entry["flows"] += 1
                entry["detections"] += detection
            entry["roles"].add(role)
            if entry["first_ts"] is None or ts < entry["first_ts"]:
                entry["first_ts"] = ts
            if entry["last_ts"] is None or ts > entry["last_ts"]:
                entry["last_ts"] = ts
    out = []
    for entry in stats.values():
        entry.pop("_rows", None)
        out.append({**entry, "roles": sorted(entry["roles"])})
    out.sort(key=lambda e: (-e["flows"], e["host"]))
    return out


def _related_domains(rows: list[dict]) -> list[dict]:
    """SNI domains behind the window's flows (newest window, sorted by flows)."""
    stats: dict[str, dict] = {}
    for row in rows:
        domain = str(row.get("sni") or "").strip().rstrip(".").lower()
        if not domain:
            continue
        ts = float(row.get("last_ts") or row.get("ts") or 0.0)
        entry = stats.get(domain)
        if entry is None:
            entry = stats[domain] = {
                "domain": domain, "flows": 0, "detections": 0,
                "first_ts": None, "last_ts": None}
        if row.get("id") not in entry.setdefault("_rows", set()):
            entry["_rows"].add(row.get("id"))
            entry["flows"] += 1
            if row.get("anomaly"):
                entry["detections"] += 1
        if entry["first_ts"] is None or ts < entry["first_ts"]:
            entry["first_ts"] = ts
        if entry["last_ts"] is None or ts > entry["last_ts"]:
            entry["last_ts"] = ts
    out = []
    for entry in stats.values():
        entry.pop("_rows", None)
        out.append(entry)
    out.sort(key=lambda e: (-e["flows"], e["domain"]))
    return out


def _annotations(rows: list[dict], alerts: list[dict]) -> dict:
    """PQC / behavioural (bio) / edge-slice annotations, refs included."""
    pqc: list[dict] = []
    bio: list[dict] = []
    edge: list[dict] = []
    for row in rows:
        ref = f"flow:{row.get('id')}"
        if row.get("pqc"):
            pqc.append({"ref": ref, "assessment": row["pqc"]})
        behaviour = {key: row[key] for key in ("immune", "snn_score", "swarm_flag")
                     if row.get(key) is not None}
        if behaviour:
            bio.append({"ref": ref, **behaviour})
        if row.get("slice"):
            edge.append({"ref": ref, "slice": row["slice"]})
    for alert in alerts:
        ref = f"alert:{alert.get('alert_id')}"
        annotations = alert.get("module_annotations") or {}
        if annotations.get("pqc"):
            pqc.append({"ref": ref, "assessment": annotations["pqc"]})
        behaviour = {key: annotations[key]
                     for key in ("immune", "snn_score", "swarm_flag")
                     if annotations.get(key) is not None}
        if behaviour:
            bio.append({"ref": ref, **behaviour})
        slice_id = (alert.get("metadata") or {}).get("slice")
        if slice_id:
            edge.append({"ref": ref, "slice": slice_id})
    return {
        "pqc": pqc[:_MAX_ANNOTATIONS],
        "bio": bio[:_MAX_ANNOTATIONS],
        "edge": edge[:_MAX_ANNOTATIONS],
        "counts": {"pqc": len(pqc), "bio": len(bio), "edge": len(edge)},
    }


__all__ = [
    "InvestigationError",
    "InvestigationUnavailable",
    "InvestigationNotFound",
    "InvestigationValidationError",
    "InvestigationService",
]
