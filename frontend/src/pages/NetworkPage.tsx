import { useState, type FormEvent } from "react";
import {
  Empty,
  ErrorBox,
  KV,
  Locked,
  Loading,
  PageHeader,
} from "../components/states";
import { api, type GraphNode, type GraphSnapshot } from "../lib/api";
import { formatBytes, formatNum } from "../lib/format";
import { useFetch } from "../lib/useFetch";

interface Props {
  can: (permission: string) => boolean;
}

interface NeighborResult {
  node: GraphNode;
  in: { source: string; type: string; weight: number }[];
  out: { target: string; type: string; weight: number }[];
}

/**
 * Network: the cross-domain correlation graph (Module 7) — summary, node
 * and edge tables with type/sector filters, and one-hop neighbour lookup
 * for any node id an analyst is investigating.
 */
export default function NetworkPage({ can }: Props) {
  const [ntype, setNtype] = useState("");
  const [sector, setSector] = useState("");
  const [lookupId, setLookupId] = useState("");
  const [lookup, setLookup] = useState<NeighborResult | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [looking, setLooking] = useState(false);

  const allowed = can("investigate");

  const graph = useFetch<GraphSnapshot>(
    () => api.graphSnapshot({ ntype: ntype || undefined, sector: sector || undefined, limit: 500 }),
    [ntype, sector],
    { enabled: allowed },
  );

  const summary = graph.data?.summary;
  const typeOptions = Object.keys(summary?.by_type ?? {}).sort();
  const sectorOptions = Object.keys(summary?.by_sector ?? {}).sort();

  const findNode = async (event: FormEvent) => {
    event.preventDefault();
    const id = lookupId.trim();
    if (!id) return;
    setLooking(true);
    setLookupError(null);
    setLookup(null);
    try {
      setLookup(await api.graphNode(id));
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : String(err));
    } finally {
      setLooking(false);
    }
  };

  if (!allowed) {
    return (
      <>
        <PageHeader
          title="Network"
          subtitle="Cross-domain correlation graph: hosts, domains, sectors, shared infrastructure."
        />
        <Locked
          permission="investigate"
          title="Network graph is restricted"
          note="The correlation graph joins detection data across domains — it requires the “investigate” permission."
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Network"
        subtitle="Correlation graph: hosts, domains and sectors observed across flows and detections."
        actions={
          <button className="ghost" onClick={graph.reload}>
            Refresh
          </button>
        }
      />

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Graph summary</h2>
        {graph.loading && !graph.data && <Loading label="Loading graph…" />}
        {graph.error && <ErrorBox message={graph.error} onRetry={graph.reload} />}
        {summary && (
          <>
            <div className="health-metrics">
              <div className="health-metric">
                <span className="health-metric-label">nodes</span>
                <span className="health-metric-value">{formatNum(summary.nodes)}</span>
              </div>
              <div className="health-metric">
                <span className="health-metric-label">edges</span>
                <span className="health-metric-value">{formatNum(summary.edges)}</span>
              </div>
              <div className="health-metric">
                <span className="health-metric-label">shared infra IPs</span>
                <span className="health-metric-value">
                  {formatNum(summary.shared_infrastructure)}
                </span>
              </div>
              {Object.entries(summary.by_type).map(([type, count]) => (
                <div className="health-metric" key={type}>
                  <span className="health-metric-label">{type}s</span>
                  <span className="health-metric-value">{formatNum(count)}</span>
                </div>
              ))}
            </div>
            <div className="kv-list" style={{ marginTop: 10 }}>
              <KV k="sectors">
                {Object.entries(summary.by_sector)
                  .map(([name, flows]) => `${name} (${flows} flows)`)
                  .join(", ") || "—"}
              </KV>
              <KV k="shared infrastructure">
                <span className="mono">
                  {summary.shared_ip_nodes.join(", ") || "—"}
                </span>
              </KV>
            </div>
          </>
        )}
      </section>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Filters &amp; node lookup</h2>
        <div className="controls">
          <label>
            Node type
            <select value={ntype} onChange={(e) => setNtype(e.target.value)}>
              <option value="">any</option>
              {typeOptions.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Sector
            <select value={sector} onChange={(e) => setSector(e.target.value)}>
              <option value="">any</option>
              {sectorOptions.map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <button
            className="ghost"
            onClick={() => {
              setNtype("");
              setSector("");
            }}
          >
            Clear
          </button>
          <form className="controls" style={{ flex: 1 }} onSubmit={findNode}>
            <label style={{ flex: 1, minWidth: 220 }}>
              Node id (host:…, ip:…, domain:…, sector:…)
              <input
                value={lookupId}
                placeholder="host:10.0.0.5"
                onChange={(e) => setLookupId(e.target.value)}
              />
            </label>
            <button type="submit" disabled={!lookupId.trim() || looking}>
              {looking ? "Looking…" : "Inspect"}
            </button>
          </form>
        </div>
        {lookupError && <ErrorBox message={lookupError} />}
        {lookup && (
          <div className="kv-list" style={{ marginTop: 10 }}>
            <KV k="node">
              <span className="mono">
                {lookup.node.label || lookup.node.id} ({lookup.node.type})
              </span>
            </KV>
            <KV k="flows / bytes / detections">
              {formatNum(lookup.node.flows ?? 0)} / {formatBytes(lookup.node.bytes ?? 0)} /{" "}
              {formatNum(lookup.node.detections ?? 0)}
            </KV>
            <KV k="in-edges">
              {lookup.in.length === 0
                ? "—"
                : lookup.in
                    .map((edge) => `${edge.source} --${edge.type}--> (${edge.weight})`)
                    .join(", ")}
            </KV>
            <KV k="out-edges">
              {lookup.out.length === 0
                ? "—"
                : lookup.out
                    .map((edge) => `--${edge.type}--> ${edge.target} (${edge.weight})`)
                    .join(", ")}
            </KV>
          </div>
        )}
      </section>

      <div className="grid two-col">
        <section className="panel">
          <h2>Nodes {graph.data ? `(${graph.data.nodes.length} of ${summary?.nodes ?? 0})` : ""}</h2>
          {graph.data && graph.data.nodes.length === 0 && (
            <Empty
              message="No nodes"
              hint="The graph fills as flows are observed — process a capture or start a live capture."
            />
          )}
          {graph.data && graph.data.nodes.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Node</th>
                    <th>Type</th>
                    <th>Sector</th>
                    <th>Flows</th>
                    <th>Bytes</th>
                    <th>Detections</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.data.nodes.map((node) => (
                    <tr
                      key={node.id}
                      style={{ cursor: "pointer" }}
                      title="Inspect this node"
                      onClick={() => {
                        setLookupId(node.id);
                        setLookup(null);
                        setLookupError(null);
                      }}
                    >
                      <td className="mono">{node.label || node.id}</td>
                      <td className="dim">{node.type}</td>
                      <td className="dim">{node.sector ?? "—"}</td>
                      <td>{formatNum(node.flows ?? 0)}</td>
                      <td>{formatBytes(node.bytes ?? 0)}</td>
                      <td>{formatNum(node.detections ?? 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Edges {graph.data ? `(${graph.data.edges.length})` : ""}</h2>
          {graph.data && graph.data.edges.length === 0 && (
            <Empty message="No edges" hint="Edges appear once relationships are observed." />
          )}
          {graph.data && graph.data.edges.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Relation</th>
                    <th>Target</th>
                    <th>Weight</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.data.edges.map((edge, index) => (
                    <tr key={`${edge.source}:${edge.target}:${edge.type}:${index}`}>
                      <td className="mono">{edge.source}</td>
                      <td className="dim">{edge.type}</td>
                      <td className="mono">{edge.target}</td>
                      <td>{edge.weight}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
