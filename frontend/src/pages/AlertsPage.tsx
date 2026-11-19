import { useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  Banner,
  Card,
  CodeValue,
  DataTable,
  Drawer,
  Eyebrow,
  EvidenceList,
  KeyValue,
  ScoreMeter,
  Select,
  SeverityBadge,
  SkewButton,
  StatusPill,
  TimeValue,
  type Column,
} from "../components/ui";
import { ApiError, type ModelInfo, type ThreatAlert } from "../lib/api";

/** The detector flags flows above the 100·(1−contamination) percentile of its training flows (docs/ml.md). */
export function scoreThreshold(model: ModelInfo | undefined): number | null {
  if (!model?.trained || !model.contamination) return null;
  return Math.round(100 * (1 - model.contamination) * 10) / 10;
}

const SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATUS_TONE = { OPEN: "warn", ACKNOWLEDGED: "live", RESOLVED: "ok" } as const;

export function BeaconNote({ type }: { type: string }) {
  if (type !== "C2_BEACONING") return null;
  return (
    <Badge tone="blue" title="See docs/guide/alerts.md: the beacon detector failed its pre-registered gate twice">
      Ranking aid, not a proven detector
    </Badge>
  );
}

function threatLabel(t: string) {
  return t === "UNKNOWN_ANOMALY" ? "Unusual, no named category" : t.replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

interface Props {
  alerts: ThreatAlert[];
  loading: boolean;
  model: ModelInfo | undefined;
  canTriage: boolean;
  triage: (alertId: string, action: "acknowledge" | "resolve") => Promise<void>;
}

/** Alerts (P0-2): every alert says why, with score + threshold, and is triaged from a drawer. */
export default function AlertsPage({ alerts, loading, model, canTriage, triage }: Props) {
  const [status, setStatus] = useState("OPEN");
  const [severity, setSeverity] = useState("any");
  const [openId, setOpenId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const threshold = scoreThreshold(model);

  const rows = useMemo(
    () => alerts.filter((a) => (status === "any" || a.status === status) && (severity === "any" || a.severity === severity)),
    [alerts, status, severity],
  );
  const open = alerts.find((a) => a.alert_id === openId) ?? null;

  const act = async (action: "acknowledge" | "resolve") => {
    if (!open) return;
    setBusy(true);
    setError(null);
    try {
      await triage(open.alert_id, action);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError(`${err.message}. Someone may have changed it already; the list now shows its current state.`);
      } else if (err instanceof ApiError && err.status === 403) {
        setError("You do not have permission to change alerts (needs incidents:manage).");
      } else setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const columns: Column<ThreatAlert>[] = [
    { key: "sev", header: "Severity", sort: (a) => SEV_ORDER.indexOf(a.severity), render: (a) => <SeverityBadge level={a.severity} /> },
    {
      key: "type",
      header: "What",
      sort: (a) => a.threat_type,
      render: (a) => (
        <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
          {threatLabel(a.threat_type)}
          {a.threat_type === "C2_BEACONING" ? <span className="sx-hint">· ranking aid</span> : null}
        </span>
      ),
    },
    { key: "score", header: "Score", align: "right", sort: (a) => a.anomaly_score, render: (a) => (a.anomaly_score === null ? "unscored" : a.anomaly_score.toFixed(1)) },
    { key: "conf", header: "Confidence", align: "right", sort: (a) => a.confidence, render: (a) => a.confidence.toFixed(2) },
    { key: "src", header: "Source", code: (a) => a.source },
    { key: "dst", header: "Destination", code: (a) => a.destination },
    { key: "n", header: "Seen", align: "right", sort: (a) => a.occurrences, render: (a) => `${a.occurrences}×` },
    { key: "last", header: "Last seen", sort: (a) => a.last_seen, render: (a) => <TimeValue ts={a.last_seen} /> },
    {
      key: "status",
      header: "Status",
      sort: (a) => a.status,
      render: (a) => <StatusPill status={STATUS_TONE[a.status] as "warn" | "live" | "ok"}>{a.status.toLowerCase()}</StatusPill>,
    },
  ];

  const meta = (open?.metadata ?? {}) as Record<string, unknown>;
  const metaRow = (label: string, key: string, code = false): [ReactNode, ReactNode] => {
    const v = meta[key];
    const text = Array.isArray(v) ? v.join(", ") : v === null || v === undefined || v === "" ? null : String(v);
    return [label, text ? code ? <CodeValue value={text} label={label} /> : text : null];
  };

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Banner title="How to read an alert">
        An alert means a flow looked unusual for this network. It is not proof of an attack: open it and weigh the evidence.
        {threshold !== null ? ` Flows score above ${threshold} of 100 (the top ${(100 - threshold).toFixed(1)} % of the baseline) to be flagged.` : ""}
      </Banner>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
        <div style={{ width: 200 }}>
          <Select
            label="Status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            options={[
              { value: "OPEN", label: "Open" },
              { value: "ACKNOWLEDGED", label: "Acknowledged" },
              { value: "RESOLVED", label: "Resolved" },
              { value: "any", label: "Any status" },
            ]}
          />
        </div>
        <div style={{ width: 200 }}>
          <Select
            label="Severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            options={[{ value: "any", label: "Any severity" }, ...[...SEV_ORDER].reverse().map((s) => ({ value: s, label: s.toLowerCase() }))]}
          />
        </div>
      </div>
      <DataTable
        caption="Alerts"
        columns={columns}
        rows={loading && alerts.length === 0 ? null : rows}
        loading={loading}
        rowKey={(a) => a.alert_id}
        onRowClick={(a) => {
          setError(null);
          setOpenId(a.alert_id);
        }}
        selectedKey={openId}
        initialSort={{ key: "sev", dir: "desc" }}
        empty={{
          title: status === "OPEN" ? "No open alerts" : "No alerts match",
          body: model && !model.trained ? "No model is trained, so nothing is scored and no alerts can be raised yet." : "Alerts appear when a processed flow is unusual for this network.",
        }}
      />

      <Drawer open={open !== null} onClose={() => setOpenId(null)} title={open ? threatLabel(open.threat_type) : "Alert"}>
        {open ? (
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <SeverityBadge level={open.severity} />
              <StatusPill status={STATUS_TONE[open.status] as "warn" | "live" | "ok"}>{open.status.toLowerCase()}</StatusPill>
              <BeaconNote type={open.threat_type} />
            </div>
            <p style={{ color: "var(--text-1)" }}>{open.evidence.summary}</p>
            {threshold !== null ? (
              <ScoreMeter score={open.anomaly_score} threshold={threshold} />
            ) : (
              <Banner tone="warn" title="No threshold to compare">
                The active model is not trained, so this score cannot be compared with a threshold.
              </Banner>
            )}
            <KeyValue
              rows={[
                ["Confidence", <span className="sx-mono">{open.confidence.toFixed(2)} <span className="sx-hint">(rule agreement on the category, never 1.00)</span></span>],
                ["Source", <CodeValue value={open.source} label="source" />],
                ["Destination", <CodeValue value={open.destination} label="destination" />],
                ["Seen", `${open.occurrences} time${open.occurrences === 1 ? "" : "s"}`],
                ["First seen", <TimeValue ts={open.first_seen} />],
                ["Last seen", <TimeValue ts={open.last_seen} />],
                ["Capture", open.capture_id !== null ? `#${open.capture_id}` : null],
                ["Model", open.model_version ? <span className="sx-mono">{open.model_version}</span> : null],
              ]}
            />
            <div style={{ display: "grid", gap: 8 }}>
              <Eyebrow as="h3">Evidence</Eyebrow>
              <EvidenceList
                supporting={open.evidence.supporting.map((e) => ({ label: e.label, value: e.value === null ? "not measured" : String(e.value), unit: e.unit ?? undefined, detail: e.detail }))}
                contradicting={open.evidence.contradicting.map((e) => ({ label: e.label, value: e.value === null ? "not measured" : String(e.value), unit: e.unit ?? undefined, detail: e.detail }))}
              />
            </div>
            <Card title="Why this severity" eyebrow="Severity factors">
              <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
                {open.severity_factors.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </Card>
            <Card title="Handshake metadata" eyebrow="Flow">
              <KeyValue
                rows={[
                  metaRow("Server name (SNI)", "sni"),
                  metaRow("TLS", "tls_version"),
                  metaRow("QUIC", "quic_version"),
                  metaRow("ALPN", "alpn"),
                  metaRow("JA3", "ja3", true),
                  metaRow("JA4", "ja4", true),
                  metaRow("Packets", "packets"),
                  metaRow("Bytes", "bytes"),
                ]}
              />
            </Card>
            {error ? (
              <Banner tone="error" title="Not changed">
                {error}
              </Banner>
            ) : null}
            {canTriage ? (
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                {open.status === "OPEN" ? (
                  <SkewButton loading={busy} onClick={() => act("acknowledge")}>
                    Acknowledge
                  </SkewButton>
                ) : null}
                {open.status !== "RESOLVED" ? (
                  <SkewButton variant="ghost" loading={busy} onClick={() => act("resolve")}>
                    Resolve
                  </SkewButton>
                ) : null}
              </div>
            ) : (
              <p className="sx-hint">Read only: acknowledging and resolving need the incidents:manage permission.</p>
            )}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
