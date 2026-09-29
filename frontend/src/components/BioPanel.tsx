import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api, type BioStatus } from "../lib/api";

/** Weight bars scale to the swarm's W_MAX (3.0) pheromone ceiling. */
const W_MAX = 3.0;

function Row({ k, v, title }: { k: string; v: ReactNode; title?: string }) {
  return (
    <div className="kv" title={title}>
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  );
}

export default function BioPanel({ onError }: { onError: (msg: string) => void }) {
  const [s, setS] = useState<BioStatus | null>(null);

  const load = useCallback(async () => {
    try {
      setS(await api.bioStatus());
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }, [onError]);

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [load]);

  if (!s) return <div className="empty">Loading immune layer…</div>;
  if (!s.available)
    return (
      <div className="empty">
        Bio layer unavailable — retrain the model (<code>spectra train</code>) to build the
        self-model, SNN baseline, and swarm.
      </div>
    );

  const hist = s.response_histogram ?? {};
  const responses = ["ignore", "monitor", "alert", "isolate"];
  const total = responses.reduce((n, r) => n + (hist[r] ?? 0), 0) || 1;
  const weights = s.swarm.agents.map((a) => [a, s.swarm.weights[a] ?? 0] as const);

  return (
    <div className="grid two-col">
      <section className="panel">
        <h2>Self model · SNN</h2>
        <Row
          k="Self model"
          v={s.self_model.trained ? `trained · ${s.self_model.n_features} features` : "not trained"}
        />
        <Row k="Assessed flows" v={s.assessed} />
        <Row
          k="Danger contour (drift)"
          v={s.drift_level ?? "quiet"}
          title="ambient drift feeding the immune danger axis"
        />
        <Row k="Evasion watch" v={s.evasion_active ? "active" : "quiet"} />
        <Row k="Timing scale (NTN)" v={`×${s.timing_scale}`} title="edge link timing multiplier" />
        <div style={{ marginTop: 14 }}>
          <div className="kv">
            <span className="k">Spiking network</span>
            <span className="v">
              {s.snn.trained ? (
                <>
                  trained · flags at ≥ {s.snn.threshold_pct}%{" "}
                  <span className="dim">(metric {s.snn.threshold?.toFixed(2)})</span>
                </>
              ) : (
                "not trained"
              )}
            </span>
          </div>
        </div>
        <p className="note">
          The self-model measures how closely each flow matches Spectra's own statistical
          shape (median / MAD affinity); the SNN fires on deviant <em>timing</em> — spike
          earliness weighted, so slow-onset anomalies still surface.
        </p>
      </section>

      <section className="panel">
        <h2>Immune responses</h2>
        <div className="kv">
          <span className="k">Memory cells</span>
          <span className="v">
            {s.memory_cells} <span className="dim">(tolerance 0.75 · cap 32)</span>
          </span>
        </div>
        {responses.map((r) => {
          const n = hist[r] ?? 0;
          return (
            <div className="bar-row" key={r}>
              <span className={`tag imm-${r}`}>{r}</span>
              <div className="bar">
                <div className={`bar-fill imm-${r}`} style={{ width: `${(n / total) * 100}%` }} />
              </div>
              <span className="bar-num">{n}</span>
            </div>
          );
        })}
        <p className="note">
          Response bands derive from affinity × danger signals; slice policy may escalate
          them (e.g. URLLC raises every response one level — see the Edge tab).
        </p>
      </section>

      <section className="panel" style={{ gridColumn: "1 / -1" }}>
        <h2>Swarm pheromones</h2>
        <div className="kv">
          <span className="k">Quorum</span>
          <span className="v">
            ≥ {s.swarm.quorum} over {s.swarm.min_agents}+ agents · {s.swarm.agents.length}{" "}
            agents
          </span>
        </div>
        {weights.map(([agent, w]) => (
          <div className="bar-row" key={agent}>
            <span className="tag">{agent}</span>
            <div className="bar">
              <div
                className="bar-fill swarm"
                style={{ width: `${Math.min(100, (w / W_MAX) * 100)}%` }}
              />
            </div>
            <span className="bar-num">{w.toFixed(2)}</span>
          </div>
        ))}
        <p className="note">
          Agents vote on every flow; agreement reinforces pheromone (×1.06, cap {W_MAX}),
          dissent decays it (×0.97). Weights steer quorum confidence, not detections — the
          bio layer never creates alerts on its own.
        </p>
      </section>
    </div>
  );
}
