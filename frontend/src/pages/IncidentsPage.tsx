import { useMemo, useState, type FormEvent } from "react";
import { Empty, ErrorBox, Locked, Loading, PageHeader, Pager } from "../components/states";
import {
  api,
  type IncidentRow,
  type IncidentStatus,
  type SearchResults,
} from "../lib/api";
import {
  formatScore,
  formatTs,
  incidentStatusClass,
  relTime,
  severityClass,
} from "../lib/format";
import { navigate } from "../lib/router";
import { useFetch } from "../lib/useFetch";

const STATUSES: IncidentStatus[] = [
  "OPEN",
  "INVESTIGATING",
  "ACKNOWLEDGED",
  "RESOLVED",
  "FALSE_POSITIVE",
];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const PAGE_SIZE = 25;

interface Props {
  can: (permission: string) => boolean;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}

/** Render one /api/search section row with its most telling fields. */
function SearchItem({
  item,
  onClick,
}: {
  item: Record<string, unknown>;
  onClick?: () => void;
}) {
  const text = (key: string) =>
    item[key] == null ? null : String(item[key]);
  const id = text("id") ?? text("alert_id") ?? text("capture_id") ?? text("host") ?? text("domain") ?? text("sni") ?? "?";
  const label =
    text("title") ??
    text("threat_type") ??
    text("proto") ??
    text("label") ??
    text("version") ??
    "";
  return (
    <li
      className={onClick ? "search-item linked" : "search-item"}
      onClick={onClick}
    >
      <span className="mono">{id}</span>
      {label && <span>{label}</span>}
      {text("status") && <span className="dim">{text("status")}</span>}
      {(text("src") || text("dst")) && (
        <span className="dim mono">
          {text("src")} → {text("dst")}
        </span>
      )}
      {item["current"] === true && <span className="tag">current</span>}
    </li>
  );
}

/**
 * Incidents: the triage queue. Server-side filters (status/severity/threat),
 * client-side narrowing over the returned page (affected host, confidence),
 * a global identifier search, and correlation of related alerts.
 */
export default function IncidentsPage({ can, onError, onNotice }: Props) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [threatType, setThreatType] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [minConfidence, setMinConfidence] = useState("");
  const [offset, setOffset] = useState(0);
  const [correlating, setCorrelating] = useState(false);

  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);

  const list = useFetch(
    () =>
      api.incidents({
        status: (status || undefined) as IncidentStatus | undefined,
        severity: severity || undefined,
        threat_type: threatType || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    [status, severity, threatType, offset],
    { enabled: can("investigate") },
  );

  const search = useFetch<SearchResults>(
    () => api.search(submitted as string),
    [submitted],
    { enabled: can("investigate") && submitted !== null },
  );

  const rows = useMemo(() => {
    let items = list.data?.items ?? [];
    const host = hostFilter.trim().toLowerCase();
    if (host) {
      items = items.filter((row) =>
        (row.affected_entities ?? []).some((entity) =>
          entity.toLowerCase().includes(host),
        ),
      );
    }
    const min = Number(minConfidence);
    if (minConfidence && !Number.isNaN(min)) {
      items = items.filter(
        (row) => row.confidence != null && row.confidence >= min / 100,
      );
    }
    return items;
  }, [list.data, hostFilter, minConfidence]);

  const canManage = can("incidents:manage");

  const correlate = async () => {
    setCorrelating(true);
    try {
      const result = await api.correlateIncidents();
      onNotice(
        `Correlation considered ${result.considered} alert(s): ` +
          `${result.clusters} incident(s) created, ${result.ungrouped.length} left ungrouped.`,
      );
      list.reload();
    } catch (err) {
      onError(
        `Correlation failed — ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setCorrelating(false);
    }
  };

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = query.trim();
    if (trimmed) setSubmitted(trimmed);
  };

  if (!can("investigate")) {
    return (
      <>
        <PageHeader
          title="Incidents"
          subtitle="Correlated, analyst-owned security incidents with lifecycle state."
        />
        <Locked
          permission="investigate"
          title="Incident queue is restricted"
          note="Incidents group detections with correlation context across the platform — they require the “investigate” permission."
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Correlated, analyst-owned security incidents with lifecycle state."
        actions={
          <>
            <button className="ghost" onClick={list.reload}>
              Refresh
            </button>
            <button disabled={!canManage || correlating} onClick={correlate} title={canManage ? "Cluster related unassigned alerts" : "Requires incidents:manage"}>
              {correlating ? "Correlating…" : "Correlate alerts"}
            </button>
          </>
        }
      />

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Filters</h2>
        <div className="controls">
          <label>
            Status
            <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
              <option value="">any</option>
              {STATUSES.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Severity
            <select value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}>
              <option value="">any</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Threat type
            <input
              value={threatType}
              placeholder="e.g. C2_BEACONING"
              onChange={(e) => { setThreatType(e.target.value); setOffset(0); }}
            />
          </label>
          <label>
            Affected host contains
            <input
              value={hostFilter}
              placeholder="e.g. 10.0.0."
              onChange={(e) => setHostFilter(e.target.value)}
            />
          </label>
          <label>
            Min confidence %
            <input
              type="number"
              min={0}
              max={100}
              value={minConfidence}
              placeholder="0–100"
              onChange={(e) => setMinConfidence(e.target.value)}
            />
          </label>
        </div>

        <form className="controls" style={{ marginTop: 12 }} onSubmit={submitSearch}>
          <label style={{ flex: 1, minWidth: 240 }}>
            Global search (id, IP, domain, JA3/JA4, model id)
            <input
              value={query}
              placeholder="e.g. 10.0.0.5, example.com, incident 3…"
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <button type="submit" disabled={!query.trim()}>Search</button>
          {submitted && (
            <button type="button" className="ghost" onClick={() => { setSubmitted(null); setQuery(""); }}>
              Clear
            </button>
          )}
        </form>

        {submitted && (
          <div style={{ marginTop: 12 }}>
            {search.loading && <Loading label="Searching…" />}
            {search.error && <ErrorBox message={search.error} onRetry={search.reload} />}
            {search.data && (
              <>
                <p className="note">
                  “{search.data.query}” classified as {search.data.kinds.join(", ") || "text"} —{" "}
                  {search.data.count} hit(s).
                </p>
                {search.data.count === 0 && (
                  <Empty message="No matches" hint="Try an IP, domain, alert id or JA3/JA4 fingerprint." />
                )}
                {Object.entries(search.data.results)
                  .filter(([, section]) => section.count > 0)
                  .map(([name, section]) => (
                    <div key={name} style={{ marginBottom: 10 }}>
                      <h3 className="search-heading">
                        {name} · {section.count}
                      </h3>
                      <ul className="search-list">
                        {section.items.slice(0, 5).map((item, index) => {
                          const incidentId =
                            name === "incidents" && typeof item["id"] === "number"
                              ? (item["id"] as number)
                              : null;
                          return (
                            <SearchItem
                              key={index}
                              item={item}
                              onClick={
                                incidentId
                                  ? () => navigate(`#/incidents/${incidentId}`)
                                  : undefined
                              }
                            />
                          );
                        })}
                      </ul>
                    </div>
                  ))}
              </>
            )}
          </div>
        )}
      </section>

      <section className="panel">
        <h2>Incident queue</h2>
        {list.loading && !list.data && <Loading label="Loading incidents…" />}
        {list.error && <ErrorBox message={list.error} onRetry={list.reload} />}
        {list.data && (
          <>
            {list.data.items.length === 0 ? (
              <Empty
                message="No incidents match"
                hint="Correlate related alerts to create one, or clear the filters."
              />
            ) : rows.length === 0 ? (
              <Empty
                message="No rows after client-side narrowing"
                hint="The affected-host / confidence filters apply to this page only — clear them to see the full page."
              />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Title</th>
                      <th>Status</th>
                      <th>Severity</th>
                      <th>Threat</th>
                      <th>Affected</th>
                      <th>Conf</th>
                      <th>First seen</th>
                      <th>Last seen</th>
                      <th>Alerts</th>
                      <th>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((incident: IncidentRow) => (
                      <tr
                        key={incident.id}
                        style={{ cursor: "pointer" }}
                        onClick={() => navigate(`#/incidents/${incident.id}`)}
                        title="Open investigation"
                      >
                        <td className="mono">{incident.id}</td>
                        <td>{incident.title}</td>
                        <td>
                          <span className={`status ${incidentStatusClass(incident.status)}`}>
                            {incident.status}
                          </span>
                        </td>
                        <td>
                          {incident.severity ? (
                            <span className={`severity ${severityClass(incident.severity)}`}>
                              {incident.severity}
                            </span>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                        <td>{incident.primary_threat_class ?? <span className="dim">—</span>}</td>
                        <td className="mono">
                          {(incident.affected_entities ?? []).slice(0, 3).join(", ")}
                          {(incident.affected_entities ?? []).length > 3 ? " …" : ""}
                        </td>
                        <td>{formatScore((incident.confidence ?? 0) * 100)}%</td>
                        <td className="dim" title={formatTs(incident.first_seen)}>
                          {relTime(incident.first_seen ?? incident.created_at)}
                        </td>
                        <td className="dim" title={formatTs(incident.last_seen)}>
                          {relTime(incident.last_seen ?? incident.created_at)}
                        </td>
                        <td>{incident.alert_count}</td>
                        <td>{incident.note_count ?? 0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager
              shown={list.data.items.length}
              total={list.data.count}
              offset={list.data.offset}
              limit={PAGE_SIZE}
              onChange={setOffset}
            />
          </>
        )}
      </section>
    </>
  );
}
