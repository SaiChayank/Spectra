"""FastAPI application: REST + WebSocket events for the dashboard."""

from __future__ import annotations

import asyncio
import time

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .. import __version__
from ..capture import CaptureError
from ..config import get_config
from ..pipeline import SpectraEngine
from ..store import StoreError

cfg = get_config()
_BOOT_TS = time.time()

app = FastAPI(title="Spectra API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = SpectraEngine(config=cfg)

# Rebuild the correlation graph from persisted history so cross-domain
# queries work immediately after an API restart (and after each capture,
# which resets the live view before re-hydrating it).
engine.hydrate_graph()


class CaptureRequest(BaseModel):
    mode: str = Field(pattern="^(pcap|live)$")
    path: str | None = None
    iface: str | None = None
    bpf_filter: str = ""


class TrainRequest(BaseModel):
    pcap_path: str
    contamination: float = Field(default=0.02, gt=0.0, lt=1.0)


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "service": "spectra",
        "version": __version__,
        "database": "enabled" if engine.store else "disabled",
        "uptime_s": round(time.time() - _BOOT_TS, 1),
    }


@app.get("/api/status")
def status() -> dict:
    return engine.status


@app.get("/api/stats")
def stats() -> dict:
    return engine.snapshot()


@app.get("/api/flows")
def flows(limit: int = 100) -> dict:
    items = list(engine.flows)[-min(limit, 1000):][::-1]
    return {"count": len(engine.flows), "items": items}


@app.get("/api/detections")
def detections(limit: int = 100) -> dict:
    items = list(engine.detections)[-min(limit, 1000):][::-1]
    return {"count": len(engine.detections), "items": items}


@app.post("/api/capture/start")
def capture_start(req: CaptureRequest) -> dict:
    try:
        return engine.start(req.mode, path=req.path, iface=req.iface,
                            bpf_filter=req.bpf_filter)
    except CaptureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/capture/stop")
def capture_stop() -> dict:
    return engine.stop()


@app.get("/api/model")
def model_info() -> dict:
    return engine.detector.info()


@app.post("/api/model/train")
def model_train(req: TrainRequest) -> dict:
    try:
        return engine.train_from_pcap(req.pcap_path, contamination=req.contamination)
    except CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class RobustnessRequest(BaseModel):
    pcap_path: str | None = None
    max_features: int = Field(12, ge=1, le=64)
    max_rounds: int = Field(6, ge=1, le=20)


@app.get("/api/model/drift")
def model_drift() -> dict:
    """PSI of recent traffic against the training baseline (Module 3)."""
    return engine.drift_report()


@app.get("/api/model/evasion")
def model_evasion() -> dict:
    """Near-threshold score clustering analysis (Module 3)."""
    return engine.evasion_watch()


@app.post("/api/model/robustness")
def model_robustness(req: RobustnessRequest) -> dict:
    """White-box evasion attack against the detector; measures robustness."""
    if req.pcap_path:
        import os

        if not os.path.isfile(req.pcap_path):
            raise HTTPException(status_code=404,
                                detail=f"PCAP not found: {req.pcap_path}")
    try:
        return engine.robustness(pcap=req.pcap_path,
                                 max_features=req.max_features,
                                 max_rounds=req.max_rounds)
    except Exception as exc:  # noqa: BLE001 - surface attack failures
        raise HTTPException(status_code=500,
                            detail=f"robustness evaluation failed: {exc}") from exc


@app.get("/api/interfaces")
def interfaces() -> dict:
    """List capture interfaces. Empty until Npcap/libpcap is installed."""
    try:
        from scapy.all import get_if_list

        return {"interfaces": get_if_list()}
    except Exception as exc:  # noqa: BLE001 - live capture unavailable
        return {"interfaces": [], "error": str(exc)}


# -- history (SQLite-backed) -------------------------------------------------


def _store_or_400():
    if engine.store is None:
        raise HTTPException(status_code=409, detail="persistence is disabled")
    return engine.store


@app.get("/api/history/flows")
def history_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
    sni: str | None = None,
) -> dict:
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=False, since=since, sni=sni
        )
    except StoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/history/detections")
def history_detections(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    since: float | None = None,
) -> dict:
    try:
        return _store_or_400().query_flows(
            limit=limit, offset=offset, anomaly_only=True, since=since
        )
    except StoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/history/captures")
def history_captures(limit: int = Query(20, ge=1, le=500)) -> dict:
    return {"items": _store_or_400().recent_captures(limit)}


@app.get("/api/history/stats")
def history_stats() -> dict:
    return _store_or_400().stats()


@app.get("/api/history/model-runs")
def history_model_runs(limit: int = Query(20, ge=1, le=200)) -> dict:
    return {"items": _store_or_400().model_runs(limit)}


# -- Module 1: PQC readiness -------------------------------------------------


# -- Module 7: cross-domain correlation --------------------------------------


@app.get("/api/graph")
def graph_view(ntype: str | None = None, sector: str | None = None,
               limit: int = Query(500, ge=1, le=2000)) -> dict:
    """Full graph (nodes + edges) for the dashboard visualisation."""
    return engine.graph_snapshot(ntype=ntype, sector=sector, limit=limit)


@app.get("/api/graph/summary")
def graph_summary() -> dict:
    return engine.graph.summary()


@app.get("/api/graph/node")
def graph_node(id: str) -> dict:
    result = engine.graph.neighbors(id)
    if result["node"] is None:
        raise HTTPException(status_code=404, detail=f"unknown node: {id}")
    return result


@app.get("/api/graph/cascade")
def graph_cascade(id: str, depth: int = Query(4, ge=1, le=8)) -> dict:
    """Blast-radius / kill-chain score starting from a node."""
    result = engine.graph_cascade(id, max_depth=depth)
    if not result["found"]:
        raise HTTPException(status_code=404, detail=f"unknown node: {id}")
    return result


@app.get("/api/graph/path")
def graph_path(src: str, dst: str) -> dict:
    path = engine.graph.shortest_path(src, dst)
    if path is None:
        raise HTTPException(status_code=404, detail="no path between nodes")
    return {"src": src, "dst": dst, "hops": len(path) - 1, "path": path}


@app.get("/api/pqc")
def pqc_report(sector: str | None = None, roadmap: bool = True) -> dict:
    """Quantum posture of everything seen by the running engine."""
    return engine.pqc_snapshot(include_roadmap=roadmap, sector=sector)


@app.get("/api/pqc/inventory")
def pqc_inventory(sector: str | None = None, limit: int = Query(200, ge=1, le=1000)) -> dict:
    snap = engine.pqc_snapshot(include_roadmap=False, sector=sector)
    return {"summary": snap["summary"],
            "endpoints": snap["endpoints"][:limit]}


@app.get("/api/pqc/scan")
def pqc_scan(pcap: str, sector: str | None = None) -> dict:
    """Run an offline PQC readiness scan over a PCAP file."""
    import os

    from ..modules.pqc.scan import scan_pcap

    if not os.path.isfile(pcap):
        raise HTTPException(status_code=400, detail=f"PCAP not found: {pcap}")
    try:
        return scan_pcap(pcap, sector=sector)
    except Exception as exc:  # noqa: BLE001 - surface scan failures to the client
        raise HTTPException(status_code=500, detail=f"scan failed: {exc}") from exc


class CertificateRequest(BaseModel):
    profile: str = Field("hipaa", pattern="^(hipaa|pci_dss|gdpr)$")
    since: float | None = None
    until: float | None = None
    min_flows: int = Field(1, ge=0)
    disclose: int = Field(3, ge=0, le=50)
    bits: int = Field(32, ge=1, le=64)


class CertificateVerifyRequest(BaseModel):
    certificate: dict


class SimulateRequest(BaseModel):
    initial: list[str] | None = None
    seed: int = 7
    rounds: int = Field(12, ge=1, le=256)
    capability: float = Field(0.6, ge=0.0, le=1.0)
    monitoring: float | None = Field(None, ge=0.0, le=1.0)
    controls: dict = Field(default_factory=dict)
    actions: list[dict] = Field(default_factory=list)


class PlaybookRequest(SimulateRequest):
    name: str | None = None
    playbook: dict | None = None


class ShadowRequest(BaseModel):
    pcap: str | None = None
    contamination: float = Field(0.05, gt=0.0, lt=1.0)
    threshold: float = Field(3.5, gt=0.0)
    retrain: bool = True


def _sim_kwargs(req: SimulateRequest) -> dict:
    return {
        "initial": req.initial,
        "seed": req.seed,
        "rounds": req.rounds,
        "capability": req.capability,
        "monitoring": req.monitoring,
        "controls": req.controls,
    }


# -- Module 5: ZKP audit trail ------------------------------------------------


@app.get("/api/audit/entries")
def audit_entries(limit: int = Query(50, ge=1, le=500),
                  offset: int = Query(0, ge=0),
                  kind: str | None = None) -> dict:
    """Hash-chained audit entries (newest first)."""
    return engine.audit_entries(limit=limit, offset=offset, kind=kind)


@app.get("/api/audit/head")
def audit_head() -> dict:
    return engine.audit_head()


@app.get("/api/audit/verify")
def audit_verify() -> dict:
    """Full chain verification: sequence, prev links, entry hashes."""
    return engine.audit_verify()


@app.post("/api/audit/checkpoint")
def audit_checkpoint() -> dict:
    """Merkle-root + Schnorr-sign everything since the previous checkpoint."""
    from ..modules.audit import AuditError

    try:
        return engine.audit_checkpoint()
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/audit/checkpoint/verify")
def audit_checkpoint_verify(seq: int | None = Query(None, ge=1)) -> dict:
    from ..modules.audit import AuditError

    try:
        return engine.audit_verify_checkpoint(seq)
    except AuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/audit/proof")
def audit_proof(seq: int = Query(..., ge=1),
                leaf: int = Query(..., ge=0)) -> dict:
    """Merkle inclusion proof for one committed flow record."""
    try:
        return engine.audit_proof(seq, leaf)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/audit/certificate")
def audit_certificate(req: CertificateRequest) -> dict:
    """Issue a signed compliance certificate (ZK claims + selective disclosure)."""
    from ..modules.audit import CertificateError

    try:
        return engine.certify(profile=req.profile, since=req.since,
                              until=req.until, min_flows=req.min_flows,
                              disclose=req.disclose, bits=req.bits)
    except CertificateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/audit/certificate/verify")
def audit_certificate_verify(req: CertificateVerifyRequest) -> dict:
    """Independently verify a certificate bundle (no database needed)."""
    return engine.verify_certificate(req.certificate)


# -- Module 4: digital twin ---------------------------------------------------


@app.get("/api/twin/topology")
def twin_topology(min_flows: int = Query(1, ge=0, le=10_000)) -> dict:
    """Twin replica: assets, zones, propagation edges, criticality."""
    return engine.twin_topology(min_flows=min_flows)


@app.get("/api/twin/playbooks")
def twin_playbooks() -> dict:
    return engine.twin_playbooks()


@app.post("/api/twin/simulate")
def twin_simulate(req: SimulateRequest) -> dict:
    """Deterministic attack-propagation run (seedable, paired draws)."""
    from ..modules.twin import SimulationError

    try:
        return engine.twin_simulate(actions=req.actions, **_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/twin/playbook")
def twin_playbook(req: PlaybookRequest) -> dict:
    """Rehearse a playbook: before/after metrics + pass/fail verdict."""
    from ..modules.twin import SimulationError

    try:
        return engine.twin_validate(name=req.name, playbook=req.playbook,
                                    **_sim_kwargs(req))
    except (SimulationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/twin/evaluate")
def twin_evaluate(req: SimulateRequest) -> dict:
    """Rehearse every library playbook against one scenario, ranked."""
    from ..modules.twin import SimulationError

    try:
        return engine.twin_evaluate(**_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/twin/recommend")
def twin_recommend(req: SimulateRequest) -> dict:
    """Auto-generate a containment playbook from current detections + rehearse."""
    from ..modules.twin import SimulationError

    try:
        return engine.twin_recommend(**_sim_kwargs(req))
    except SimulationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/twin/shadow")
def twin_shadow(req: ShadowRequest) -> dict:
    """Shadow-mode comparison: production vs legacy z-score rule (+ candidate)."""
    if req.pcap:
        import os

        if not os.path.isfile(req.pcap):
            raise HTTPException(status_code=404, detail=f"PCAP not found: {req.pcap}")
    try:
        return engine.shadow(pcap=req.pcap, contamination=req.contamination,
                             threshold=req.threshold, retrain=req.retrain)
    except Exception as exc:  # noqa: BLE001 - surface shadow failures
        raise HTTPException(status_code=500,
                            detail=f"shadow run failed: {exc}") from exc


# -- Module 6: bio-inspired detection --------------------------------------


class BioAssessRequest(BaseModel):
    features: list[float] | None = None
    score: float | None = Field(None, ge=0, le=100)
    anomaly: bool = False


@app.get("/api/bio/status")
def bio_status() -> dict:
    """Immune self-model, SNN calibration, swarm pheromones, memory cells."""
    return engine.bio_report()


@app.post("/api/bio/assess")
def bio_assess(req: BioAssessRequest) -> dict:
    """Danger-theory response for one flow (explicit vector or latest)."""
    from ..features.extractor import N_FEATURES

    if req.features is not None and len(req.features) != N_FEATURES:
        raise HTTPException(
            status_code=400,
            detail=f"expected {N_FEATURES} features, "
                   f"got {len(req.features)}")
    try:
        return engine.bio_assess(req.features, score=req.score,
                                 anomaly=req.anomaly)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# -- Module 2: confidential computing / TEE --------------------------------


class TeeAttestRequest(BaseModel):
    nonce: str | None = None


class TeeVerifyRequest(BaseModel):
    quote: dict
    measurement: str | None = None
    max_age: float = Field(600.0, gt=0)
    nonce: str | None = None


class TeeInferRequest(BaseModel):
    features: list[float]


class TeeFederateRequest(BaseModel):
    deltas: list[list[float]] | None = None
    shareholders: int = Field(3, ge=2, le=16)
    seed: int = 7


@app.post("/api/tee/attest")
def tee_attest(req: TeeAttestRequest) -> dict:
    """Nonce-bound signed quote of the model measurement."""
    from ..modules.tee import TeeError

    try:
        return engine.tee_attest(req.nonce)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tee/verify")
def tee_verify(req: TeeVerifyRequest) -> dict:
    """Verify a quote: signature, provenance, freshness, measurement."""
    from ..modules.tee import TeeError

    try:
        return engine.tee_verify(req.quote, measurement=req.measurement,
                                 max_age=req.max_age, nonce=req.nonce)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tee/infer")
def tee_infer(req: TeeInferRequest) -> dict:
    """Protected inference: features in, score + sealed receipt out."""
    from ..features.extractor import N_FEATURES
    from ..modules.tee import TeeError

    if len(req.features) != N_FEATURES:
        raise HTTPException(status_code=400,
                            detail=f"expected {N_FEATURES} features, "
                                   f"got {len(req.features)}")
    try:
        return engine.tee_infer(req.features)
    except TeeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tee/federate")
def tee_federate(req: TeeFederateRequest) -> dict:
    """Additive secret-sharing round over explicit deltas or the live window."""
    from ..modules.tee import FederatedError, TeeError

    try:
        return engine.tee_federate(deltas=req.deltas,
                                   shareholders=req.shareholders,
                                   seed=req.seed)
    except (FederatedError, TeeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# -- Module 8: 5G/6G edge ---------------------------------------------------


class EdgeLinkRequest(BaseModel):
    link: str = Field(min_length=1)


class EdgeDeployRequest(BaseModel):
    node: str = Field(min_length=1)
    slice: str = Field("default", pattern="^(urllc|embb|mmtc|default)$")


class EdgeSliceRequest(BaseModel):
    record: dict
    level: int = Field(2, ge=0, le=3)


@app.get("/api/edge/report")
def edge_report() -> dict:
    """Slices, micro-detector state, NTN link profiles, deployments."""
    return engine.edge_report()


@app.post("/api/edge/link")
def edge_link(req: EdgeLinkRequest) -> dict:
    """Switch the non-terrestrial backhaul profile (NTN support)."""
    from ..modules.edge import EdgeError

    try:
        return engine.edge_set_link(req.link)
    except EdgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/edge/deploy")
def edge_deploy(req: EdgeDeployRequest) -> dict:
    """Register a micro-detector deployment on a MEC node."""
    from ..modules.edge import EdgeError

    try:
        return engine.edge_deploy(req.node, req.slice)
    except EdgeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/edge/slice")
def edge_slice(req: EdgeSliceRequest) -> dict:
    """Classify a flow record onto a slice and preview its policy."""
    from ..modules.edge import SLICES, apply_slice_policy, classify_slice

    slice_id = classify_slice(req.record)
    adjusted, note = apply_slice_policy(req.level, slice_id)
    return {
        "slice": slice_id,
        "policy": SLICES[slice_id],
        "level": req.level,
        "adjusted_level": adjusted,
        "note": note,
    }


@app.get("/api/metrics")
def metrics() -> str:
    """Prometheus text exposition format."""
    snap = engine.snapshot()
    status = snap["status"]
    totals = snap["totals"]
    model = snap["model"]
    lines = [
        "# TYPE spectra_packets_total counter",
        f"spectra_packets_total {status['packets']}",
        "# TYPE spectra_flows_total counter",
        f"spectra_flows_total {totals['flows']}",
        "# TYPE spectra_detections_total counter",
        f"spectra_detections_total {totals['detections']}",
        "# TYPE spectra_anomaly_rate gauge",
        f"spectra_anomaly_rate {totals['anomaly_rate']}",
        "# TYPE spectra_avg_score gauge",
        f"spectra_avg_score {totals['avg_score'] if totals['avg_score'] is not None else -1}",
        "# TYPE spectra_capture_running gauge",
        f"spectra_capture_running {1 if status['running'] else 0}",
        "# TYPE spectra_model_trained gauge",
        f"spectra_model_trained {1 if model['trained'] else 0}",
        "# TYPE spectra_model_train_flows gauge",
        f"spectra_model_train_flows {model['n_train']}",
        "# TYPE spectra_uptime_seconds gauge",
        f"spectra_uptime_seconds {round(time.time() - _BOOT_TS, 1)}",
    ]
    for proto, n in snap["protocols"].items():
        lines.append(f'spectra_flows_by_proto{{proto="{proto}"}} {n}')
    return "\n".join(lines) + "\n"


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    await ws.accept()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=500)

    def _put(event: dict) -> None:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:  # slow client: drop oldest to keep stream fresh
            try:
                queue.get_nowait()
                queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    unsubscribe = engine.subscribe(lambda e: loop.call_soon_threadsafe(_put, e))
    await ws.send_json({"type": "status", "data": engine.status})

    async def _reader() -> None:
        while True:
            await ws.receive_text()  # client messages are ignored (keepalive/ping)

    async def _writer() -> None:
        while True:
            await ws.send_json(await queue.get())

    reader_task = asyncio.create_task(_reader())
    writer_task = asyncio.create_task(_writer())
    try:
        await asyncio.wait({reader_task, writer_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (reader_task, writer_task):
            task.cancel()
        unsubscribe()
        try:
            await ws.close()
        except RuntimeError:  # already closed by the client
            pass
