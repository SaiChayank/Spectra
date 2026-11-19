import { Suspense, lazy, useCallback, useEffect, useState } from "react";
import Landing from "./components/Landing";
import { LoginScreen, type LoginNotice } from "./components/LoginPanel";
import { Banner, Loading, SkewButton, SkewTabs, StorageBanner, UntrainedBanner } from "./components/ui";
import {
  ApiError,
  NetworkError,
  api,
  type Detection,
  type FlowRecord,
  type Identity,
  type Snapshot,
  type ThreatAlert,
  type WsEvent,
} from "./lib/api";
import { EXPERIMENTAL_LABELS, SECTION_LABELS, useRoute, type Section } from "./lib/router";
import { useEvents } from "./lib/useEvents";
import Shell, { type LiveState } from "./shell/Shell";
import { useConnection } from "./shell/useConnection";
import { startPage, startupSession } from "./lib/session";
import AlertsPage from "./pages/AlertsPage";
import CapturesPage from "./pages/CapturesPage";

// heavier pages load on first visit (smaller first bundle)
const OverviewPage = lazy(() => import("./pages/OverviewPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const IncidentDetailPage = lazy(() => import("./pages/IncidentDetailPage"));
const ModelsPage = lazy(() => import("./pages/ModelsPage"));
const ModulesPage = lazy(() => import("./pages/ModulesPage"));
const NetworkPage = lazy(() => import("./pages/NetworkPage"));
const TrafficPage = lazy(() => import("./pages/TrafficPage"));
const SystemPage = lazy(() => import("./pages/SystemPage"));
const MonitorPage = lazy(() => import("./pages/MonitorPage"));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage"));
const AccountPage = lazy(() => import("./pages/AccountPage"));
const HostsPage = lazy(() => import("./pages/HostsPage"));

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

  // A new tab or window starts signed out on the landing page: any leftover
  // session cookie is ended first. A reload in the same tab restores the
  // session from the HttpOnly cookie instead.
  useEffect(() => {
    let live = true;
    startupSession().then((id) => {
      if (!live) return;
      setIdentity(id);
      setAuthChecked(true);
    });
    return () => {
      live = false;
    };
  }, []);

  // A 401 anywhere in the app ends the session: go to sign-in with a message,
  // remembering where the analyst was (in memory only) to return there after.
  const [returnTo, setReturnTo] = useState<string | null>(null);
  const [loginNotice, setLoginNotice] = useState<LoginNotice | null>(null);
  useEffect(() => {
    const onUnauthorized = () => {
      const here = window.location.hash;
      if (here && here !== "#/" && here !== "#/login") setReturnTo(here);
      setLoginNotice({ tone: "warn", title: "Your session ended", body: "Sign in again to continue where you left off." });
      setIdentity(null);
      window.location.hash = "#/login";
    };
    window.addEventListener("spectra:unauthorized", onUnauthorized);
    return () => window.removeEventListener("spectra:unauthorized", onUnauthorized);
  }, []);

  const [connection, clearStorage] = useConnection();
  const [incidentTab, setIncidentTab] = useState<"alerts" | "incidents">("alerts");

  // Promise chain (not async/await) so state is set in callbacks, not
  // synchronously in the polling effect.
  const refresh = useCallback(() => {
    Promise.all([api.stats(), api.flows(60), api.detections(40), api.alerts(200)])
      .then(([stats, flowList, detList, alertList]) => {
        setSnapshot(stats);
        setFlows(flowList.items);
        setDetections(detList.items);
        setAlerts(alertList.items);
        setError(null);
      })
      .catch((err: unknown) => {
        // outages have their own banners (offline / storage); 401 ends the session
        if (err instanceof NetworkError) return;
        if (err instanceof ApiError && err.status === 503) return;
        if (err instanceof Error && err.name === "AuthError") return;
        setError(`Could not refresh the dashboard: ${err instanceof Error ? err.message : String(err)}`);
      });
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

  // Alerts screen: errors go back to the drawer (409 conflicts are explained there)
  const triageAlert = async (alertId: string, action: "acknowledge" | "resolve") => {
    try {
      const updated = await (action === "acknowledge" ? api.acknowledgeAlert(alertId) : api.resolveAlert(alertId));
      setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
    } catch (err) {
      refresh(); // show the alert's current state
      throw err;
    }
  };

  const status = snapshot?.status;
  const live: LiveState = connected ? "live" : connection.offline ? "offline" : "reconnecting";

  if (!authChecked) {
    return (
      <div className="sx" style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <p role="status">Restoring session…</p>
      </div>
    );
  }

  // -- not signed in: landing at #/, sign-in at #/login; a console deep link
  //    goes to sign-in and comes back after (the landing/login redesign is step 4)
  if (!identity) {
    const deepLink = route.kind === "console";
    const pending = returnTo ?? (deepLink ? window.location.hash : null);
    const finishLogin = (next: Identity) => {
      setError(null);
      setNotice(null);
      setLoginNotice(null);
      setIdentity(next);
      setReturnTo(null);
      navigate(pending ?? startPage(next));
    };
    if (route.kind !== "login" && !deepLink) return <Landing />;
    return (
      <LoginScreen
        onLogin={finishLogin}
        notice={
          loginNotice ??
          (deepLink ? { tone: "info", title: "Sign in to continue", body: "That page needs a signed-in user." } : null)
        }
      />
    );
  }

  // -- signed in: the landing stays at #/ (with "Open console"); #/login goes to the start page
  if (route.kind === "landing") return <Landing signedIn onEnter={() => navigate(startPage(identity))} />;
  if (route.kind === "login") return <RedirectTo path={startPage(identity)} />;

  // -- signed in: console routes ------------------------------------------------
  const section: Section = route.kind === "console" ? route.section : "overview";
  const incidentId = route.kind === "console" ? route.incidentId : null;
  const module = route.kind === "console" ? route.module : null;
  const title =
    section === "incidents" && incidentId != null
      ? `Incident #${incidentId}`
      : section === "experimental" && module
        ? EXPERIMENTAL_LABELS[module]
        : SECTION_LABELS[section];

  const banners = (
    <>
      {connection.offline ? (
        <Banner tone="error" title="Cannot reach the Spectra server">
          Check that the backend is running. The console keeps retrying every few seconds; what you see may be out of date.
        </Banner>
      ) : null}
      {connection.storage ? (
        <StorageBanner
          key={connection.storage.key}
          retryAfter={connection.storage.retryAfter}
          onRetry={() => {
            clearStorage();
            refresh();
          }}
        />
      ) : null}
      {snapshot && !snapshot.model.trained ? (
        <UntrainedBanner canTrain={can("model:manage")} onTrain={() => navigate("#/captures")} />
      ) : null}
      {status?.error ? (
        <Banner tone="error" title="Capture error">
          {status.error}
        </Banner>
      ) : null}
      {error ? (
        <Banner
          tone="error"
          title="Something went wrong"
          action={
            <SkewButton variant="ghost" size="sm" onClick={() => setError(null)}>
              Dismiss
            </SkewButton>
          }
        >
          {error}
        </Banner>
      ) : null}
      {notice ? (
        <Banner
          title="Done"
          action={
            <SkewButton variant="ghost" size="sm" onClick={() => setNotice(null)}>
              Dismiss
            </SkewButton>
          }
        >
          {notice}
        </Banner>
      ) : null}
    </>
  );

  return (
    <Shell
      identity={identity}
      section={section}
      module={module}
      title={title}
      can={can}
      capture={status}
      model={snapshot?.model}
      live={live}
      onSignOut={signOut}
      banners={banners}
    >
      <Suspense fallback={<Loading label="Loading page" />}>
      {section === "overview" && <OverviewPage snapshot={snapshot} alerts={alerts} can={can} />}

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

      {section === "incidents" &&
        (incidentId != null ? (
          <IncidentDetailPage incidentId={incidentId} can={can} onError={setError} onNotice={setNotice} />
        ) : (
          <div style={{ display: "grid", gap: 16 }}>
            <SkewTabs
              label="Alerts and incidents"
              value={incidentTab}
              onChange={setIncidentTab}
              items={[
                { id: "alerts", label: `Alerts${alerts.filter((a) => a.status === "OPEN").length ? ` · ${alerts.filter((a) => a.status === "OPEN").length} open` : ""}` },
                { id: "incidents", label: "Incidents" },
              ]}
            />
            {incidentTab === "alerts" ? (
              <AlertsPage alerts={alerts} loading={snapshot === null} model={snapshot?.model} canTriage={canTriage} triage={triageAlert} />
            ) : (
              <IncidentsPage can={can} onError={setError} onNotice={setNotice} />
            )}
          </div>
        ))}

      {section === "captures" && <CapturesPage can={can} capture={status} model={snapshot?.model} onChanged={refresh} />}

      {section === "hosts" && <HostsPage />}

      {section === "traffic" && <TrafficPage can={can} />}

      {section === "network" && <NetworkPage can={can} />}

      {section === "models" && <ModelsPage can={can} onError={setError} onNotice={setNotice} />}

      {section === "audit" && <AuditPage can={can} />}

      {section === "experimental" && (
        <div style={{ display: "grid", gap: 16 }}>
          <Banner tone="warn" title="Experimental · simulated or frozen">
            These modules are software simulations or frozen by the owner's decision. They are not production security controls.
          </Banner>
          <ModulesPage can={can} onError={setError} onNotice={setNotice} />
        </div>
      )}

      {section === "system" && <SystemPage connected={connected} />}

      {section === "account" && (
        <AccountPage
          identity={identity}
          can={can}
          onSignedOut={(text) => {
            setLoginNotice({ tone: "info", title: "Signed out", body: text });
            setIdentity(null);
            navigate("#/login");
          }}
          onIdentityChanged={() => {
            api.me().then(setIdentity).catch(() => undefined);
          }}
        />
      )}
      </Suspense>
    </Shell>
  );
}

/** Navigate once after render (never during it). */
function RedirectTo({ path }: { path: string }) {
  useEffect(() => {
    window.location.hash = path;
  }, [path]);
  return null;
}
