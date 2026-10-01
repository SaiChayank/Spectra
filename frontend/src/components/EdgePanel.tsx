import { useCallback, useEffect, useState } from "react";
import CapabilityStrip from "./CapabilityStrip";
import { api, type EdgeReport, type EdgeSliceResult } from "../lib/api";

const LINK_ORDER = ["terrestrial", "uav", "leo_satellite", "geostationary"];
const SLICE_ORDER = ["urllc", "embb", "mmtc", "default"];

export default function EdgePanel({ canRun, canConfig, onError, onNotice }: {
  /** investigate permission (ANALYST/ADMIN): run the slice classifier. */
  canRun: boolean;
  /** config:manage permission (ADMIN): switch backhaul link, deploy. */
  canConfig: boolean;
  onError: (msg: string) => void;
  onNotice: (msg: string) => void;
}) {
  const [report, setReport] = useState<EdgeReport | null>(null);
  const [busy, setBusy] = useState(false);

  // slice classifier form
  const [sni, setSni] = useState("portal.hospital.example");
  const [bytes, setBytes] = useState("900");
  const [packets, setPackets] = useState("6");
  const [duration, setDuration] = useState("1.0");
  const [tls, setTls] = useState("TLS 1.3");
  const [level, setLevel] = useState(2);
  const [sliceOut, setSliceOut] = useState<EdgeSliceResult | null>(null);

  // deployment form
  const [node, setNode] = useState("mec-01");
  const [depSlice, setDepSlice] = useState("urllc");

  const load = useCallback(async () => {
    try {
      setReport(await api.edgeReport());
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }, [onError]);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  const setLink = useCallback(
    async (link: string) => {
      setBusy(true);
      try {
        const out = await api.edgeSetLink(link);
        onNotice(`Link profile → ${out.link.label} (timing ×${out.link.timing_scale})`);
        await load();
      } catch (err) {
        onError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [load, onError, onNotice],
  );

  const classify = useCallback(async () => {
    setBusy(true);
    try {
      setSliceOut(
        await api.edgeSlice(
          {
            sni: sni || null,
            bytes: Number(bytes) || 0,
            packets: Number(packets) || 0,
            duration: Number(duration) || 1,
            tls_version: tls || null,
          },
          level,
        ),
      );
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [sni, bytes, packets, duration, tls, level, onError]);

  const deploy = useCallback(async () => {
    setBusy(true);
    try {
      const out = await api.edgeDeploy(node, depSlice);
      onNotice(`Deployed micro-detector → ${out.node} (slice ${out.slice})`);
      await load();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [node, depSlice, load, onError, onNotice]);

  if (!report) return <div className="empty">Loading edge runtime…</div>;

  const lat = report.micro.latency;

  return (
    <div className="grid two-col">
      <div style={{ gridColumn: "1 / -1" }}>
        {/* data-driven maturity badges (GET /api/capabilities): LOCAL scoring
            and SIMULATED deployment come from the contract, not a hardcode */}
        <CapabilityStrip keys={["edge", "edge_deployment"]} />
        <p className="note">
          Slice and micro-detector logic runs locally; NTN link profiles and MEC
          deployments are simulations, not a real 5G control plane.
        </p>
      </div>
      <section className="panel">
        <h2>NTN backhaul link</h2>
        <div className="kv">
          <span className="k">Active</span>
          <span className="v">
            {report.link.label} · RTT {report.link.rtt_ms}ms · jitter {report.link.jitter_ms}ms ·
            timing ×{report.link.timing_scale}
          </span>
        </div>
        <div className="controls" style={{ marginTop: 12 }}>
          {LINK_ORDER.map((l) => (
            <button
              key={l}
              className={l === report.link.link ? "" : "ghost"}
              disabled={busy || !canConfig || l === report.link.link}
              title={canConfig ? undefined : "Requires config:manage (ADMIN)"}
              onClick={() => setLink(l)}
            >
              {report.link_profiles[l]?.label ?? l}
            </button>
          ))}
        </div>
        <p className="note">
          Switching the backhaul retimes flow features before scoring — satellite links must
          not read as anomalies just for being slow.
          {!canConfig && " Switching requires config:manage (ADMIN)."}
        </p>
      </section>

      <section className="panel">
        <h2>MEC micro-detector</h2>
        <div className="kv">
          <span className="k">State</span>
          <span className="v">
            {report.micro.trained ? "trained" : "not trained"} · {report.micro.n_features}{" "}
            features · flags ≥ {report.micro.threshold_pct}%
          </span>
        </div>
        <div className="kv">
          <span className="k">Digest</span>
          <span className="v mono" title={report.micro.digest}>
            {report.micro.digest.slice(0, 20)}…
          </span>
        </div>
        <div className="kv">
          <span className="k">Latency budget</span>
          <span className="v">
            {lat
              ? `p95 ${lat.p95_ms.toFixed(2)}ms / ${lat.budget_ms}ms ${
                  lat.within_budget ? "✓" : "✗"
                }`
              : `unmeasured · budget ${report.micro.budget_ms}ms`}
          </span>
        </div>
        <div className="controls" style={{ marginTop: 12 }}>
          <label>
            Node
            <input value={node} onChange={(e) => setNode(e.target.value)} spellCheck={false} />
          </label>
          <label>
            Slice
            <select value={depSlice} onChange={(e) => setDepSlice(e.target.value)}>
              {SLICE_ORDER.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={deploy}
            disabled={busy || !canConfig}
            style={{ alignSelf: "flex-end" }}
            title={canConfig ? undefined : "Requires config:manage (ADMIN)"}
          >
            Deploy
          </button>
        </div>
        {report.deployments.length > 0 && (
          <div className="table-wrap" style={{ marginTop: 12, maxHeight: 160 }}>
            <table>
              <thead>
                <tr>
                  <th>Node</th>
                  <th>Slice</th>
                  <th>Link</th>
                  <th>Deployed</th>
                </tr>
              </thead>
              <tbody>
                {report.deployments.map((d) => (
                  <tr key={d.node}>
                    <td className="mono">{d.node}</td>
                    <td>
                      <span className="tag">{d.slice}</span>
                    </td>
                    <td className="dim">{d.link}</td>
                    <td className="dim">{new Date(d.deployed_at * 1000).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <h2>Network slices</h2>
        <div className="table-wrap" style={{ maxHeight: 220 }}>
          <table>
            <thead>
              <tr>
                <th>Slice</th>
                <th>Flows</th>
                <th>Sensitivity</th>
                <th>Policy</th>
              </tr>
            </thead>
            <tbody>
              {SLICE_ORDER.map((id) => {
                const def = report.slices[id];
                if (!def) return null;
                return (
                  <tr key={id}>
                    <td>
                      <span className="tag">{id}</span>
                    </td>
                    <td>{report.slice_counts[id] ?? 0}</td>
                    <td className="dim">{def.sensitivity}</td>
                    <td className="dim">{def.policy}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="note">{report.slices.urllc?.label}</p>
      </section>

      <section className="panel">
        <h2>Slice classifier</h2>
        <div className="controls">
          <label>
            SNI
            <input value={sni} onChange={(e) => setSni(e.target.value)} spellCheck={false} />
          </label>
          <label>
            TLS
            <input value={tls} onChange={(e) => setTls(e.target.value)} spellCheck={false} />
          </label>
          <label>
            Bytes
            <input value={bytes} onChange={(e) => setBytes(e.target.value)} inputMode="numeric" />
          </label>
          <label>
            Packets
            <input
              value={packets}
              onChange={(e) => setPackets(e.target.value)}
              inputMode="numeric"
            />
          </label>
          <label>
            Duration (s)
            <input value={duration} onChange={(e) => setDuration(e.target.value)} inputMode="decimal" />
          </label>
          <label>
            Response level
            <select value={level} onChange={(e) => setLevel(Number(e.target.value))}>
              <option value={0}>0 · ignore</option>
              <option value={1}>1 · monitor</option>
              <option value={2}>2 · alert</option>
              <option value={3}>3 · isolate</option>
            </select>
          </label>
          <button
            onClick={classify}
            disabled={busy || !canRun}
            style={{ alignSelf: "flex-end" }}
            title={canRun ? undefined : "Requires investigate (ANALYST/ADMIN)"}
          >
            Classify
          </button>
        </div>
        {sliceOut && (
          <div style={{ marginTop: 12 }}>
            <div className="kv">
              <span className="k">Slice</span>
              <span className="v">
                <span className="tag">{sliceOut.slice}</span> {sliceOut.policy.label}
              </span>
            </div>
            <div className="kv">
              <span className="k">Response</span>
              <span className="v">
                level {sliceOut.level} → <strong>{sliceOut.adjusted_level}</strong>
                {sliceOut.note ? <span className="dim"> ({sliceOut.note})</span> : null}
              </span>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
