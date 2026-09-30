import { useCallback, useEffect, useState } from "react";
import BioPanel from "./components/BioPanel";
import CapturePanel from "./components/CapturePanel";
import DetectionsTable from "./components/DetectionsTable";
import EdgePanel from "./components/EdgePanel";
import FlowsTable from "./components/FlowsTable";
import LoginPanel from "./components/LoginPanel";
import StatCards from "./components/StatCards";
import TeePanel from "./components/TeePanel";
import Timeline from "./components/Timeline";
import {
  api,
  type Detection,
  type FlowRecord,
  type Identity,
  type Snapshot,
  type WsEvent,
} from "./lib/api";
import { useEvents } from "./lib/useEvents";

type Tab = "overview" | "bio" | "tee" | "edge";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "bio", label: "Bio immunity" },
  { id: "tee", label: "TEE attestation" },
  { id: "edge", label: "Edge / 5G" },
];

export default function App() {
  // -- session --------------------------------------------------------------
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  // -- dashboard data --------------------------------------------------------
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("overview");

  // Restore the session from the HttpOnly cookie on load; any failure means
  // "not signed in" — the login form collects credentials itself.
  useEffect(() => {
    api
      .me()
      .then((id) => setIdentity(id))
      .catch(() => setIdentity(null))
      .finally(() => setAuthChecked(true));
  }, []);

  // A 401 anywhere in the app ends the session: drop back to the login screen.
  useEffect(() => {
    const onUnauthorized = () => setIdentity(null);
    window.addEventListener("spectra:unauthorized", onUnauthorized);
    return () => window.removeEventListener("spectra:unauthorized", onUnauthorized);
  }, []);

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
    if (!identity) return; // don't poll while signed out
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [refresh, identity]);

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
  }, identity !== null);

  // -- role gates (the server enforces these; the UI just reflects them) -----
  const can = (permission: string) =>
    identity?.user.permissions.includes(permission) ?? false;
  const canManage = can("capture:manage") && can("model:manage");
  const canRun = can("investigate");
  const canConfig = can("config:manage");

  const signOut = async () => {
    try {
      await api.logout();
    } catch {
      /* the session may already be gone server-side */
    }
    setIdentity(null);
  };

  const status = snapshot?.status;
  const running = status?.running ?? false;

  const brand = (
    <div className="brand">
      <h1>SPECTRA</h1>
      <span className="tagline">encrypted traffic threat detection · metadata only</span>
    </div>
  );

  if (!authChecked) {
    return (
      <div className="app">
        <header className="topbar">
          {brand}
          <div className="spacer" />
        </header>
        <p className="note">Restoring session…</p>
      </div>
    );
  }

  if (!identity) {
    return (
      <div className="app">
        <header className="topbar">
          {brand}
          <div className="spacer" />
          <span className="pill">
            <span className="dot" />
            signed out
          </span>
        </header>
        <LoginPanel
          onLogin={(next) => {
            setError(null);
            setNotice(null);
            setIdentity(next);
          }}
        />
      </div>
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        {brand}
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
        <span className="pill" title={identity.user.permissions.join(", ")}>
          {identity.user.username} · {identity.user.role}
        </span>
        <button className="ghost" onClick={signOut} title="End this session">
          Sign out
        </button>
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
              <CapturePanel
                status={status}
                canManage={canManage}
                onError={setError}
                onNotice={setNotice}
              />
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
      {tab === "tee" && (
        <TeePanel canRun={canRun} onError={setError} onNotice={setNotice} />
      )}
      {tab === "edge" && (
        <EdgePanel canRun={canRun} canConfig={canConfig} onError={setError} onNotice={setNotice} />
      )}

      <p className="note">
        Spectra inspects only flow statistics and TLS handshake structure — SNI, ALPN,
        versions, cipher lists, JA3/JA4 fingerprints and timing. Payload contents are never
        decrypted, stored, or displayed.
      </p>
    </div>
  );
}
