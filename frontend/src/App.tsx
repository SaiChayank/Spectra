import { useCallback, useEffect, useState } from "react";
import BioPanel from "./components/BioPanel";
import CapturePanel from "./components/CapturePanel";
import DetectionsTable from "./components/DetectionsTable";
import EdgePanel from "./components/EdgePanel";
import FlowsTable from "./components/FlowsTable";
import StatCards from "./components/StatCards";
import TeePanel from "./components/TeePanel";
import Timeline from "./components/Timeline";
import { api, type Detection, type FlowRecord, type Snapshot, type WsEvent } from "./lib/api";
import { useEvents } from "./lib/useEvents";

type Tab = "overview" | "bio" | "tee" | "edge";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "bio", label: "Bio immunity" },
  { id: "tee", label: "TEE attestation" },
  { id: "edge", label: "Edge / 5G" },
];

export default function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  const refresh = useCallback(async () => {
    try {
      const [stats, flowList, detList] = await Promise.all([
        api.stats(),
        api.flows(60),
        api.detections(40),
      ]);
      setSnapshot(stats);
      setFlows(flowList.items);
      setDetections(detList.items);
      setError(null);
    } catch (err) {
      setError(
        `Backend unreachable (http://localhost:8787) — ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [refresh]);

  const connected = useEvents((event: WsEvent) => {
    if (event.type === "detection") {
      setDetections((prev) => [event.data, ...prev].slice(0, 40));
    } else if (event.type === "flow") {
      setFlows((prev) => [event.data, ...prev].slice(0, 60));
    } else if (event.type === "status") {
      setSnapshot((prev) => (prev ? { ...prev, status: event.data } : prev));
    } else if (event.type === "model") {
      setSnapshot((prev) => (prev ? { ...prev, model: event.data } : prev));
    }
  });

  const status = snapshot?.status;
  const running = status?.running ?? false;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>SPECTRA</h1>
          <span className="tagline">encrypted traffic threat detection · metadata only</span>
        </div>
        <div className="spacer" />
        <span className={`pill ${status?.error ? "err" : running ? "live" : ""}`}>
          <span className="dot" />
          {status?.error ? "capture error" : running ? "capturing" : "idle"}
        </span>
        <span className={`pill ${connected ? "ws" : ""}`}>
          <span className="dot" />
          {connected ? "live events" : "reconnecting"}
        </span>
        <span className={`pill ${snapshot?.model.trained ? "ws" : ""}`}>
          <span className="dot" />
          {snapshot?.model.trained ? "model ready" : "untrained"}
        </span>
      </header>

      {error && <div className="error-banner">{error}</div>}
      {notice && (
        <div className="success-banner" onClick={() => setNotice(null)}>
          {notice}
        </div>
      )}
      {status?.error && <div className="error-banner">Capture error: {status.error}</div>}

      <nav className="tabs" aria-label="Sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}
            aria-current={tab === t.id}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <>
          <StatCards snapshot={snapshot} />

          {status && (
            <div style={{ marginBottom: 16 }}>
              <CapturePanel status={status} onError={setError} onNotice={setNotice} />
            </div>
          )}

          <div style={{ marginBottom: 16 }}>
            <Timeline points={snapshot?.timeline ?? []} />
          </div>

          <div className="grid two-col" style={{ marginBottom: 16 }}>
            <DetectionsTable items={detections} />
            <FlowsTable items={flows} />
          </div>
        </>
      )}

      {tab === "bio" && <BioPanel onError={setError} />}
      {tab === "tee" && <TeePanel onError={setError} onNotice={setNotice} />}
      {tab === "edge" && <EdgePanel onError={setError} onNotice={setNotice} />}

      <p className="note">
        Spectra inspects only flow statistics and TLS handshake structure — SNI, ALPN,
        versions, cipher lists, JA3/JA4 fingerprints and timing. Payload contents are never
        decrypted, stored, or displayed.
      </p>
    </div>
  );
}
