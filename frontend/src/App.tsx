import { useCallback, useEffect, useState } from "react";
import Landing from "./components/Landing";
import LoginPanel from "./components/LoginPanel";
import {
  api,
  type Detection,
  type FlowRecord,
  type Identity,
  type Snapshot,
  type ThreatAlert,
  type WsEvent,
} from "./lib/api";
import { SECTIONS, SECTION_LABELS, useRoute, type Section } from "./lib/router";
import { useEvents } from "./lib/useEvents";
import AuditPage from "./pages/AuditPage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import IncidentsPage from "./pages/IncidentsPage";
import ModelsPage from "./pages/ModelsPage";
import MonitorPage from "./pages/MonitorPage";
import ModulesPage from "./pages/ModulesPage";
import NetworkPage from "./pages/NetworkPage";
import OverviewPage from "./pages/OverviewPage";
import SystemPage from "./pages/SystemPage";
import TrafficPage from "./pages/TrafficPage";

/** Sections the server gates behind `investigate` (shown, but restricted). */
const INVESTIGATE_ONLY: Section[] = ["incidents", "network", "audit"];

export default function App() {
  // -- session --------------------------------------------------------------
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [authChecked, setAuthChecked] = useState(false);

  // -- route (tiny hash router: #/overview, #/incidents/12, #/login) ----------
  const [route, navigate] = useRoute();

  // -- dashboard data --------------------------------------------------------
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Restore the session from the HttpOnly cookie on load; any failure means
  // "not signed in" — the landing page / login form take over.
  useEffect(() => {
    api
      .me()
      .then((id) => setIdentity(id))
      .catch(() => setIdentity(null))
      .finally(() => setAuthChecked(true));
  }, []);

  // A 401 anywhere in the app ends the session: drop back to the landing page.
  useEffect(() => {
    const onUnauthorized = () => setIdentity(null);
    window.addEventListener("spectra:unauthorized", onUnauthorized);
    return () => window.removeEventListener("spectra:unauthorized", onUnauthorized);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [stats, flowList, detList, alertList] = await Promise.all([
        api.stats(),
        api.flows(60),
        api.detections(40),
        api.alerts(40),
      ]);
      setSnapshot(stats);
      setFlows(flowList.items);
      setDetections(detList.items);
      setAlerts(alertList.items);
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
    } else if (event.type === "alert") {
      // New alert: dedupe by id (a re-sighting may already be listed).
      setAlerts((prev) =>
        [event.data, ...prev.filter((a) => a.alert_id !== event.data.alert_id)].slice(0, 40),
      );
    } else if (event.type === "alert_updated") {
      // Repeat sighting or status change: replace in place, most recent first.
      setAlerts((prev) =>
        [
          event.data,
          ...prev.filter((a) => a.alert_id !== event.data.alert_id),
        ].slice(0, 40),
      );
    }
  }, identity !== null);

  // -- role gates (the server enforces these; the UI just reflects them) -----
  const can = (permission: string) =>
    identity?.user.permissions.includes(permission) ?? false;
  const canManage = can("capture:manage") && can("model:manage");
  const canTriage = can("incidents:manage");

  const signOut = async () => {
    try {
      await api.logout();
    } catch {
      /* the session may already be gone server-side */
    }
    setIdentity(null);
    navigate("#/"); // landing page for the next visitor of this tab
  };

  // -- alert triage (OPEN -> ACKNOWLEDGED -> RESOLVED) ------------------------
  const triage = async (
    alertId: string,
    action: (id: string) => Promise<ThreatAlert>,
  ) => {
    try {
      const updated = await action(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? updated : a)),
      );
    } catch (err) {
      setError(
        `Alert transition failed — ${err instanceof Error ? err.message : String(err)}`,
      );
    }
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

  // -- not signed in: landing at #/, sign-in at #/login, deep links → landing --
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
        {route.kind === "login" ? (
          <LoginPanel
            onLogin={(next) => {
              setError(null);
              setNotice(null);
              setIdentity(next);
              navigate("#/overview");
            }}
          />
        ) : (
          <Landing />
        )}
      </div>
    );
  }

  // -- signed in: console routes (any other hash lands on Overview) ----------
  const section: Section = route.kind === "console" ? route.section : "overview";
  const incidentId = route.kind === "console" ? route.incidentId : null;

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
        {SECTIONS.map((id) => {
          const gated = !can("investigate") && INVESTIGATE_ONLY.includes(id);
          return (
            <button
              key={id}
              className={`tab ${section === id ? "active" : ""}${gated ? " gated" : ""}`}
              onClick={() => navigate(`#/${id}`)}
              aria-current={section === id}
              title={
                gated
                  ? `${SECTION_LABELS[id]} requires the investigate permission — opens in a restricted state`
                  : undefined
              }
            >
              {SECTION_LABELS[id]}
            </button>
          );
        })}
      </nav>

      {section === "overview" && (
        <OverviewPage snapshot={snapshot} alerts={alerts} can={can} />
      )}

      {section === "monitor" && (
        <MonitorPage
          snapshot={snapshot}
          flows={flows}
          detections={detections}
          alerts={alerts}
          connected={connected}
          canManage={canManage}
          canTriage={canTriage}
          triage={triage}
          onError={setError}
          onNotice={setNotice}
        />
      )}

      {section === "incidents" && (
        incidentId != null ? (
          <IncidentDetailPage
            incidentId={incidentId}
            can={can}
            onError={setError}
            onNotice={setNotice}
          />
        ) : (
          <IncidentsPage can={can} onError={setError} onNotice={setNotice} />
        )
      )}

      {section === "traffic" && <TrafficPage can={can} />}

      {section === "network" && <NetworkPage can={can} />}

      {section === "models" && (
        <ModelsPage can={can} onError={setError} onNotice={setNotice} />
      )}

      {section === "audit" && <AuditPage can={can} />}

      {section === "modules" && (
        <ModulesPage can={can} onError={setError} onNotice={setNotice} />
      )}

      {section === "system" && <SystemPage connected={connected} />}
    </div>
  );
}
