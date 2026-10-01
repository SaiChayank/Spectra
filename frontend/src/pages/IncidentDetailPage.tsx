import { useState, type FormEvent } from "react";
import FlowsTable from "../components/FlowsTable";
import {
  Empty,
  ErrorBox,
  KV,
  Locked,
  Loading,
  PageHeader,
} from "../components/states";
import {
  api,
  type BundleModuleItem,
  type EvidenceItem,
  type IncidentEvent,
  type InvestigationBundle,
} from "../lib/api";
import {
  formatNum,
  formatScore,
  formatTs,
  incidentStatusClass,
  relTime,
  severityClass,
} from "../lib/format";
import { navigate } from "../lib/router";
import { useFetch } from "../lib/useFetch";

interface Props {
  incidentId: number;
  can: (permission: string) => boolean;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}

const FLOW_PAGE = 50;

/** One evidence item as a compact labelled row. */
function EvidenceRow({ item, kind }: { item: EvidenceItem; kind: "ok" | "bad" }) {
  return (
    <div className="evidence-row">
      <span className={`evidence-mark ${kind}`}>{kind === "ok" ? "+" : "−"}</span>
      <span className="evidence-label">
        {item.label}
        {item.value != null && (
          <span className="dim">
            {" "}
            = {String(item.value)}
            {item.unit ?? ""}
          </span>
        )}
      </span>
      <span className="evidence-detail">{item.detail}</span>
    </div>
  );
}

function TimelineEntry({ entry }: { entry: IncidentEvent }) {
  let detail = "";
  try {
    detail = Object.entries(entry.data ?? {})
      .map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
      .join(" · ");
  } catch {
    detail = "";
  }
  return (
    <li className="timeline-entry">
      <span className="mono dim" title={formatTs(entry.ts)}>
        {relTime(entry.ts)}
      </span>
      <span className="tag">{entry.kind}</span>
      <span>{entry.actor}</span>
      {detail && <span className="dim">{detail}</span>}
    </li>
  );
}

function ModuleContribution({ item }: { item: BundleModuleItem }) {
  return (
    <div className="module-item">
      <div className="module-item-head">
        <span className="cap-badge">
          <span
            className={`cap-dot ${
              item.available === true ? "up" : item.available === false ? "down" : "unknown"
            }`}
          />
          <span className={`cap-status ${item.status.toLowerCase()}`}>
            {item.status}
          </span>
        </span>
        <strong>{item.title}</strong>
        <span className="badge low">{item.contributed} evidence</span>
        {item.affects_alert_scoring && <span className="badge mid">affects scoring</span>}
      </div>
      <p className="note">{item.summary || item.detail || "—"}</p>
    </div>
  );
}

/**
 * Investigation view: one bounded bundle for one incident — summary,
 * threat classification, timeline, supporting evidence, related flows,
 * TLS/QUIC metadata, correlation slice, module evidence, model identity,
 * audit references and analyst notes, plus the state-change actions.
 */
export default function IncidentDetailPage({
  incidentId,
  can,
  onError,
  onNotice,
}: Props) {
  const bundle = useFetch<InvestigationBundle>(
    () => api.investigation(incidentId),
    [incidentId],
    { enabled: can("investigate") },
  );
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [flowOffset, setFlowOffset] = useState(0);

  const data = bundle.data;
  const incident = data?.incident;
  const manage = can("incidents:manage");

  const act = async (
    label: string,
    action: () => Promise<unknown>,
  ) => {
    setBusy(true);
    try {
      await action();
      onNotice(`${label} — recorded on incident #${incidentId}.`);
      setFlowOffset(0);
      bundle.reload();
    } catch (err) {
      onError(`${label} failed — ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const submitNote = async (event: FormEvent) => {
    event.preventDefault();
    const body = note.trim();
    if (!body) return;
    await act("Note added", () => api.incidentNote(incidentId, body));
    setNote("");
  };

  if (!can("investigate")) {
    return (
      <>
        <PageHeader title={`Incident #${incidentId}`} />
        <Locked
          permission="investigate"
          title="Investigation is restricted"
          note="The full evidence bundle joins detections, flows, audit and module context — it requires the “investigate” permission."
        />
        <button className="ghost" onClick={() => navigate("#/")}>
          ← Back to overview
        </button>
      </>
    );
  }

  if (bundle.loading && !data) {
    return (
      <>
        <PageHeader title={`Incident #${incidentId}`} />
        <Loading label="Assembling investigation bundle…" />
      </>
    );
  }
  if (bundle.error) {
    return (
      <>
        <PageHeader title={`Incident #${incidentId}`} />
        <ErrorBox message={bundle.error} onRetry={bundle.reload} />
        <button className="ghost" onClick={() => navigate("#/incidents")}>
          ← Back to incidents
        </button>
      </>
    );
  }
  if (!data || !incident) return null;

  const status = incident.status;
  const isActive =
    status === "OPEN" || status === "ACKNOWLEDGED" || status === "INVESTIGATING";

  /** Strongest detector percentile across member alerts ("—" when none). */
  const maxAnomalyScore = data.alerts.items.reduce<number | null>(
    (max, alert) =>
      alert.anomaly_score == null
        ? max
        : max == null
          ? alert.anomaly_score
          : Math.max(max, alert.anomaly_score),
    null,
  );

  const actionButtons = [
    (status === "OPEN" || status === "ACKNOWLEDGED") && {
      key: "investigate",
      label: "Start investigation",
      run: () => api.incidentAction(incidentId, "investigate"),
    },
    status === "OPEN" && {
      key: "acknowledge",
      label: "Acknowledge",
      run: () => api.incidentAction(incidentId, "acknowledge"),
    },
    isActive && {
      key: "resolve",
      label: "Resolve",
      run: () => api.incidentAction(incidentId, "resolve"),
    },
    isActive && {
      key: "false-positive",
      label: "False positive",
      run: () => api.incidentAction(incidentId, "false-positive"),
    },
    (status === "RESOLVED" || status === "FALSE_POSITIVE") && {
      key: "reopen",
      label: "Reopen",
      run: () => api.incidentAction(incidentId, "reopen"),
    },
  ].filter(Boolean) as {
    key: string;
    label: string;
    run: () => Promise<unknown>;
  }[];

  return (
    <>
      <PageHeader
        title={`#${incident.id} · ${incident.title}`}
        subtitle={
          incident.summary ??
          incident.evidence_summary ??
          "No written summary — see evidence below."
        }
        actions={
          <button className="ghost" onClick={() => navigate("#/incidents")}>
            ← Incidents
          </button>
        }
      />

      <div className="detail-badges">
        <span className={`status ${incidentStatusClass(status)}`}>{status}</span>
        {incident.severity && (
          <span className={`severity ${severityClass(incident.severity)}`}>
            {incident.severity}
          </span>
        )}
        {incident.primary_threat_class && (
          <span className="tag">{incident.primary_threat_class}</span>
        )}
        <span className="badge mid">
          confidence {formatScore((incident.confidence ?? 0) * 100)}%
        </span>
        <span className="badge low">{incident.alert_count} alert(s)</span>
        <span className="badge low">{data.note_count} note(s)</span>
      </div>

      <section className="panel" style={{ margin: "14px 0" }}>
        <h2>State changes</h2>
        <div className="controls">
          {actionButtons.map((button) => (
            <button
              key={button.key}
              disabled={!manage || busy}
              title={manage ? undefined : "Requires incidents:manage"}
              onClick={() => act(button.label, button.run)}
            >
              {button.label}
            </button>
          ))}
          {actionButtons.length === 0 && (
            <span className="note">No further transitions from {status}.</span>
          )}
        </div>
        {!manage && (
          <p className="note">
            Transitions require the “incidents:manage” permission — you can
            read the full investigation without it.
          </p>
        )}
        {manage && (
          <form className="controls" style={{ marginTop: 12 }} onSubmit={submitNote}>
            <label style={{ flex: 1, minWidth: 260 }}>
              Analyst note
              <input
                value={note}
                placeholder="What did you conclude?"
                onChange={(e) => setNote(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || !note.trim()}>
              Add note
            </button>
          </form>
        )}
      </section>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Summary</h2>
          <KV k="status">{status}</KV>
          <KV k="threat classification">
            {incident.primary_threat_class ?? "—"}
          </KV>
          <KV k="anomaly score (max)">
            {maxAnomalyScore == null ? "—" : formatScore(maxAnomalyScore)}
          </KV>
          <KV k="confidence">
            {formatScore((incident.confidence ?? 0) * 100)}%
          </KV>
          <KV k="first seen">{formatTs(incident.first_seen ?? incident.created_at)}</KV>
          <KV k="last seen">{formatTs(incident.last_seen ?? incident.created_at)}</KV>
          <KV k="created by">{incident.created_by}</KV>
          <KV k="affected entities">
            <span className="mono">
              {(incident.affected_entities ?? []).join(", ") || "—"}
            </span>
          </KV>
          <KV k="model version(s)">
            {(incident.model_versions ?? []).join(", ") || "—"}
          </KV>
          <KV k="window">
            {formatTs(data.window.since)} → {formatTs(data.window.until)} (
            {formatNum(data.window.evidence_rows)} of{" "}
            {formatNum(data.window.evidence_total)} related flow(s))
          </KV>
        </section>

        <section className="panel">
          <h2>Timeline</h2>
          {data.timeline.length === 0 ? (
            <Empty message="No timeline entries yet" hint="State changes and links appear here." />
          ) : (
            <ul className="timeline-list">
              {[...data.timeline]
                .sort((a, b) => b.ts - a.ts)
                .map((entry) => (
                  <TimelineEntry key={entry.id} entry={entry} />
                ))}
            </ul>
          )}
        </section>
      </div>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Supporting evidence</h2>
        {data.evidence.summary && <p className="note">{data.evidence.summary}</p>}
        {data.evidence.severity_factors.length > 0 && (
          <p className="note">
            Severity factors: {data.evidence.severity_factors.join(" · ")}
          </p>
        )}
        <div className="grid two-col">
          <div>
            <h3 className="section-label">Alert verdicts</h3>
            {data.evidence.alerts.length === 0 && (
              <Empty message="No member alerts" />
            )}
            {data.evidence.alerts.map((alert) => (
              <div key={alert.alert_id} className="evidence-block">
                <div className="module-item-head">
                  <span className="mono">{alert.alert_id}</span>
                  <span className={`severity ${severityClass(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <strong>{alert.threat_type}</strong>
                  <span className="badge mid">
                    conf {formatScore(alert.confidence * 100)}%
                  </span>
                  <span className="badge low">
                    score {formatScore(alert.anomaly_score)}
                  </span>
                </div>
                {alert.evidence.summary && (
                  <p className="note">{alert.evidence.summary}</p>
                )}
                {alert.evidence.supporting.map((item) => (
                  <EvidenceRow key={item.key} item={item} kind="ok" />
                ))}
                {alert.evidence.contradicting.map((item) => (
                  <EvidenceRow key={item.key} item={item} kind="bad" />
                ))}
              </div>
            ))}
          </div>
          <div>
            <h3 className="section-label">Detector reasons (flagged flows)</h3>
            {data.evidence.flow_reasons.length === 0 && (
              <Empty message="No per-flow reasons in the window" />
            )}
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Flow</th>
                    <th>Score</th>
                    <th>Top reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {data.evidence.flow_reasons.map((row) => (
                    <tr key={row.flow_id}>
                      <td className="mono">{row.flow_id}</td>
                      <td>{formatScore(row.score)}</td>
                      <td className="mono">
                        {(row.reasons ?? [])
                          .slice(0, 3)
                          .map((reason) => `${reason.feature} (z ${reason.z_score.toFixed(1)})`)
                          .join(", ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Member alerts ({data.alerts.count})</h2>
          {data.alerts.items.length === 0 ? (
            <Empty message="No alerts linked" hint="Attach alerts from the alerts feed." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Threat</th>
                    <th>Sev</th>
                    <th>Conf</th>
                    <th>Source → destination</th>
                    <th>Model</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.alerts.items.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td className="mono">{alert.alert_id}</td>
                      <td>{alert.threat_type}</td>
                      <td>
                        <span className={`severity ${severityClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td>{formatScore(alert.confidence * 100)}%</td>
                      <td className="mono">
                        {alert.source} → {alert.destination}
                      </td>
                      <td className="mono dim">{alert.model_id ?? "—"}</td>
                      <td className="dim" title={formatTs(alert.last_seen)}>
                        {relTime(alert.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Related flows ({data.flows.count})</h2>
          <div className="controls" style={{ marginBottom: 10 }}>
            <button
              className="ghost"
              disabled={flowOffset === 0}
              onClick={() => setFlowOffset(Math.max(0, flowOffset - FLOW_PAGE))}
            >
              ← Newer
            </button>
            <button
              className="ghost"
              disabled={flowOffset + FLOW_PAGE >= data.flows.count}
              onClick={() => setFlowOffset(flowOffset + FLOW_PAGE)}
            >
              Older →
            </button>
            <span className="note">
              {data.flows.count === 0
                ? "no related flows"
                : `${flowOffset + 1}–${Math.min(flowOffset + FLOW_PAGE, data.flows.count)} of ${data.flows.count}`}
            </span>
          </div>
          {data.flows.items.length === 0 ? (
            <Empty message="No related flows in the window" />
          ) : (
            <FlowsTable items={data.flows.items} bare />
          )}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Source / destination hosts</h2>
          <div className="grid two-col">
            <div>
              <h3 className="section-label">Hosts</h3>
              {data.hosts.length === 0 ? (
                <Empty message="No host endpoints in the window" />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Roles</th>
                        <th>Flows</th>
                        <th>Detections</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.hosts.map((host) => (
                        <tr key={host.host}>
                          <td className="mono">{host.host}</td>
                          <td className="dim">{host.roles.join("/")}</td>
                          <td>{host.flows}</td>
                          <td>{host.detections}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            <div>
              <h3 className="section-label">Domains (SNI)</h3>
              {data.domains.length === 0 ? (
                <Empty message="No SNI domains in the window" />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Domain</th>
                        <th>Flows</th>
                        <th>Detections</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.domains.map((domain) => (
                        <tr key={domain.domain}>
                          <td className="mono">{domain.domain}</td>
                          <td>{domain.flows}</td>
                          <td>{domain.detections}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="panel">
          <h2>TLS / QUIC metadata</h2>
          <p className="note">
            Sampled {formatNum(data.tls.sampled)} of {formatNum(data.tls.flows_total)}{" "}
            related flow(s) — handshake metadata only, never payload.
          </p>
          <div className="kv-list">
            <KV k="TLS versions">
              {Object.entries(data.tls.tls_versions)
                .map(([name, count]) => `${name} ×${count}`)
                .join(", ") || "—"}
            </KV>
            <KV k="QUIC versions">
              {Object.entries(data.tls.quic_versions)
                .map(([name, count]) => `${name} ×${count}`)
                .join(", ") || "—"}
            </KV>
            <KV k="ALPN">
              {Object.entries(data.tls.alpn)
                .map(([name, count]) => `${name} ×${count}`)
                .join(", ") || "—"}
            </KV>
          </div>
          {data.tls.fingerprints.length > 0 && (
            <div className="table-wrap" style={{ marginTop: 8 }}>
              <table>
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Fingerprint</th>
                    <th>Flows</th>
                    <th>SNIs</th>
                  </tr>
                </thead>
                <tbody>
                  {data.tls.fingerprints.map((fp) => (
                    <tr key={`${fp.kind}:${fp.value}`}>
                      <td>{fp.kind.toUpperCase()}</td>
                      <td className="mono">{fp.value}</td>
                      <td>{fp.flows}</td>
                      <td className="mono dim">{fp.snis.slice(0, 3).join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Correlation graph slice</h2>
          {!data.graph.available && (
            <Empty
              message="Graph unavailable"
              hint="The correlation graph is empty until flows are observed."
            />
          )}
          {data.graph.available && (
            <>
              <p className="note">
                {data.graph.nodes.length} node(s), {data.graph.edges.length} edge(s)
                {data.graph.truncated ? " (truncated)" : ""}
                {data.graph.missing.length > 0
                  ? `, ${data.graph.missing.length} referenced node(s) missing`
                  : ""}
              </p>
              <div className="grid two-col">
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Node</th>
                        <th>Type</th>
                        <th>Flows</th>
                        <th>Detections</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.graph.nodes.map((node) => (
                        <tr key={node.id}>
                          <td className="mono">{node.label || node.id}</td>
                          <td className="dim">{node.type}</td>
                          <td>{node.flows ?? 0}</td>
                          <td>{node.detections ?? 0}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Edge</th>
                        <th>Type</th>
                        <th>Weight</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.graph.edges.map((edge, index) => (
                        <tr key={`${edge.source}:${edge.target}:${edge.type}:${index}`}>
                          <td className="mono">
                            {edge.source} → {edge.target}
                          </td>
                          <td className="dim">{edge.type}</td>
                          <td>{edge.weight}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              {data.twin.available && data.twin.summary && (
                <p className="note">
                  Digital twin context: {data.twin.summary.nodes} node(s),{" "}
                  {data.twin.summary.assets} asset(s) across{" "}
                  {data.twin.summary.zones} zone(s) (simulated blast radius).
                </p>
              )}
            </>
          )}
        </section>

        <section className="panel">
          <h2>Module evidence</h2>
          <p className="note">{data.modules.scoring_policy}</p>
          <div className="kv-list">
            <KV k="PQC annotations">{data.annotations.counts.pqc}</KV>
            <KV k="behavioural annotations">{data.annotations.counts.bio}</KV>
            <KV k="edge slice tags">{data.annotations.counts.edge}</KV>
            <KV k="audit references">{data.audit.count}</KV>
          </div>
          <div style={{ marginTop: 10 }}>
            {data.modules.items.map((item) => (
              <ModuleContribution key={item.key} item={item} />
            ))}
          </div>
        </section>
      </div>

      <div className="grid two-col">
        <section className="panel">
          <h2>Model identity</h2>
          <KV k="current model">
            <span className="mono">
              {(data.models.current["id"] as string) ??
                (data.models.current["trained"] ? "trained detector" : "untrained")}
            </span>
          </KV>
          <KV k="models seen on this incident">
            {data.models.versions.length > 0
              ? data.models.versions.join(", ")
              : "—"}
          </KV>
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table>
              <thead>
                <tr>
                  <th>Alert</th>
                  <th>Model id</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {data.models.alerts.map((row) => (
                  <tr key={row.alert_id}>
                    <td className="mono">{row.alert_id}</td>
                    <td className="mono">{row.model_id ?? "—"}</td>
                    <td className="dim">{row.model_version ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <h2>Audit references ({data.audit.count})</h2>
          {data.audit.items.length === 0 ? (
            <Empty message="No audit entries reference this incident yet" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Kind</th>
                    <th>Actor</th>
                    <th>When</th>
                    <th>Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {data.audit.items.map((entry) => (
                    <tr key={entry.seq}>
                      <td className="mono">{entry.seq}</td>
                      <td>{entry.kind}</td>
                      <td>{entry.actor ?? "—"}</td>
                      <td className="dim">{formatTs(entry.ts)}</td>
                      <td className="mono dim">{entry.entry_hash.slice(0, 10)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <button className="ghost" style={{ marginTop: 8 }} onClick={() => navigate("#/audit")}>
            Open audit trail
          </button>
        </section>
      </div>

      {data.notes.length > 0 && (
        <section className="panel" style={{ marginTop: 16 }}>
          <h2>Analyst notes ({data.note_count})</h2>
          <ul className="timeline-list">
            {[...data.notes]
              .sort((a, b) => b.created_at - a.created_at)
              .map((entry) => (
                <li className="timeline-entry" key={entry.id}>
                  <span className="mono dim" title={formatTs(entry.created_at)}>
                    {relTime(entry.created_at)}
                  </span>
                  <span className="tag">{entry.author}</span>
                  <span>{entry.body}</span>
                </li>
              ))}
          </ul>
        </section>
      )}
    </>
  );
}
