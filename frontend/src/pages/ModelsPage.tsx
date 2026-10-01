import { useState, type FormEvent } from "react";
import {
  Empty,
  ErrorBox,
  KV,
  Loading,
  PageHeader,
} from "../components/states";
import {
  api,
  type CaptureResource,
  type DriftReport,
  type ModelInfo,
  type ModelRun,
  type RegistryCompare,
  type RegistryList,
  type RegistryRow,
} from "../lib/api";
import {
  formatNum,
  formatTs,
  parseJson,
  registryStatusClass,
  relTime,
  shortHash,
} from "../lib/format";
import { useFetch } from "../lib/useFetch";

interface Props {
  can: (permission: string) => boolean;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}

/** Status → the transitions the service will accept (model_registry.py). */
function actionsFor(row: RegistryRow): string[] {
  switch (row.status) {
    case "CANDIDATE":
      return ["validate", "retire"];
    case "VALIDATED":
      return ["activate", "retire"];
    case "RETIRED":
      return ["activate"];
    default:
      return []; // ACTIVE (already running), FAILED (no legal transition)
  }
}

function Checks({ row }: { row: RegistryRow }) {
  const checks = row.metrics?.checks ?? [];
  if (row.error) {
    return <p className="note">Error: {row.error}</p>;
  }
  if (row.metrics?.failed?.length) {
    return (
      <p className="note">
        Validation failed: {row.metrics.failed.join(" · ")}
      </p>
    );
  }
  if (checks.length === 0) {
    return <p className="note">Not validated yet.</p>;
  }
  return (
    <ul className="check-list">
      {checks.map((check) => (
        <li key={check.name} className={check.ok ? "ok" : "bad"}>
          <span className="check-mark">{check.ok ? "✓" : "✗"}</span>
          <span className="mono">{check.name}</span>
          {check.detail && <span className="dim">{check.detail}</span>}
        </li>
      ))}
    </ul>
  );
}

/**
 * Models: the active detector, the full registry (Prompt 14 lifecycle with
 * validate / activate / retire / rollback, gated on model:manage), training
 * with an explicit activation choice, drift, feature schema and lineage.
 */
export default function ModelsPage({ can, onError, onNotice }: Props) {
  const manage = can("model:manage");
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [compareA, setCompareA] = useState("");
  const [compareB, setCompareB] = useState("");
  const [diff, setDiff] = useState<RegistryCompare | null>(null);
  const [compareError, setCompareError] = useState<string | null>(null);

  // Training form.
  const [captureId, setCaptureId] = useState("");
  const [contamination, setContamination] = useState("0.02");
  const [activate, setActivate] = useState(true);
  const [trainResult, setTrainResult] = useState<string | null>(null);

  const model = useFetch<ModelInfo>(() => api.model(), []);
  const registry = useFetch<RegistryList>(() => api.registryList(), [], {
    intervalMs: 20000,
  });
  const captures = useFetch<{ count: number; items: CaptureResource[] }>(
    () => api.listCaptures(100),
    [],
    { enabled: manage },
  );
  const drift = useFetch<DriftReport>(() => api.modelDrift(), [], {
    enabled: can("investigate"),
  });
  const runs = useFetch<{ count: number; items: ModelRun[] }>(
    () => api.historyModelRuns({ limit: 10 }),
    [],
  );

  const refreshAll = () => {
    registry.reload();
    model.reload();
    runs.reload();
  };

  /** Run one registry transition with a per-row busy key. */
  const transition = async (key: string, label: string, action: () => Promise<RegistryRow>) => {
    setBusyKey(key);
    try {
      const row = await action();
      const suffix =
        row.applied === false
          ? " — promoted, but session side effects failed (see system health)."
          : "";
      onNotice(`${label}: ${row.model_id} is now ${row.status}.${suffix}`);
      setDiff(null);
      refreshAll();
    } catch (err) {
      onError(`${label} failed — ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyKey(null);
    }
  };

  const rollback = async () => {
    setBusyKey("rollback");
    try {
      const row = await api.registryRollback();
      onNotice(`Rollback: ${row.model_id} reactivated (${relTime(row.last_activated_at)}).`);
      setDiff(null);
      refreshAll();
    } catch (err) {
      onError(`Rollback failed — ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyKey(null);
    }
  };

  const compare = async (event: FormEvent) => {
    event.preventDefault();
    if (!compareA || !compareB) return;
    setCompareError(null);
    setDiff(null);
    try {
      setDiff(await api.registryCompare(compareA, compareB));
    } catch (err) {
      setCompareError(err instanceof Error ? err.message : String(err));
    }
  };

  const train = async (event: FormEvent) => {
    event.preventDefault();
    if (!captureId) return;
    const contaminationValue = Number(contamination);
    if (Number.isNaN(contaminationValue) || contaminationValue <= 0 || contaminationValue >= 0.5) {
      onError("Contamination must be between 0 and 0.5 (fraction of training rows assumed anomalous).");
      return;
    }
    setBusyKey("train");
    setTrainResult(null);
    try {
      const result = await api.train(Number(captureId), contaminationValue, activate);
      const reg = result.registry;
      setTrainResult(
        `Trained on ${formatNum(result.n_train)} row(s) → ${result.model_path}` +
          (reg
            ? `. Registry: ${reg.model_id} is ${reg.status}` +
              (reg.activated ? " and ACTIVE" : " (candidate — activate when ready)") +
              (reg.applied === false ? " — session side effects failed." : ".")
            : " (persistence off — not registered)."),
      );
      onNotice("Training complete.");
      refreshAll();
    } catch (err) {
      onError(`Training failed — ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusyKey(null);
    }
  };

  const info = model.data;
  const active = registry.data?.active ?? null;
  const rows = registry.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Models"
        subtitle="Active detector, registry lifecycle (candidate → validated → active → retired), training, drift and lineage."
        actions={
          <button className="ghost" onClick={refreshAll}>
            Refresh
          </button>
        }
      />

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Active model</h2>
          {model.loading && !model.data && <Loading label="Loading model…" />}
          {model.error && <ErrorBox message={model.error} onRetry={model.reload} />}
          {info && (
            <>
              <KV k="ready">{info.trained ? "yes" : "no — train a baseline"}</KV>
              <KV k="threshold">{info.threshold ?? "—"}</KV>
              <KV k="training rows">{formatNum(info.n_train)}</KV>
              <KV k="contamination">{info.contamination}</KV>
              <KV k="estimators">{info.n_estimators}</KV>
              <KV k="trained at">
                {info.trained_at
                  ? new Date(info.trained_at).toLocaleString()
                  : "—"}
              </KV>
              <KV k="model version">{info.version}</KV>
              <KV k="feature schema">
                <span className="chip-row">
                  {(info.feature_names ?? []).map((name) => (
                    <span className="tag" key={name}>{name}</span>
                  ))}
                  {(info.feature_names ?? []).length === 0 && `${info.n_features} features`}
                </span>
              </KV>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Registry row (single ACTIVE)</h2>
          {registry.loading && !registry.data && <Loading label="Loading registry…" />}
          {registry.error && (
            <ErrorBox message={registry.error} onRetry={registry.reload} />
          )}
          {registry.data && !registry.data.enabled && (
            <Empty
              message="Registry disabled"
              hint="Persistence is off — model lineage is not recorded in this run."
            />
          )}
          {registry.data?.enabled && !active && (
            <Empty
              message="No ACTIVE model"
              hint="Register one by training (below) or validate an existing candidate."
            />
          )}
          {active && (
            <>
              <KV k="model id">
                <span className="mono">{active.model_id}</span>
              </KV>
              <KV k="status">
                <span className={`badge ${registryStatusClass(active.status)}`}>
                  {active.status}
                </span>
              </KV>
              <KV k="artifact sha256">
                <span className="mono">{shortHash(active.artifact_sha256, 20)}</span>
              </KV>
              <KV k="source">{active.source}</KV>
              <KV k="threshold">{active.threshold ?? "—"}</KV>
              <KV k="training rows">{formatNum(active.n_train)}</KV>
              <KV k="activations">
                {active.activated_count} · last {relTime(active.last_activated_at)}
              </KV>
              <KV k="feature schema digest">
                <span className="mono">{shortHash(active.feature_schema, 16)}</span>
              </KV>
            </>
          )}
          {manage && (
            <button
              className="ghost"
              style={{ marginTop: 8 }}
              disabled={busyKey === "rollback" || !active || !manage}
              title={
                !manage
                  ? "Requires model:manage"
                  : !active
                    ? "No active model to roll back from"
                    : "Re-activate the most recently superseded model"
              }
              onClick={rollback}
            >
              {busyKey === "rollback" ? "Rolling back…" : "Rollback to previous"}
            </button>
          )}
        </section>
      </div>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Registry models {registry.data ? `(${registry.data.count})` : ""}</h2>
        {registry.data?.enabled && rows.length === 0 && (
          <Empty
            message="Registry is empty"
            hint="Train a model below — it registers, validates and activates with full audit."
          />
        )}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Status</th>
                  <th>Source</th>
                  <th>Trained</th>
                  <th>Threshold</th>
                  <th>SHA-256</th>
                  <th>Created</th>
                  <th>Activations</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <Row
                    key={row.model_id}
                    row={row}
                    manage={manage}
                    busy={busyKey !== null}
                    busyKey={busyKey}
                    expanded={expanded === row.model_id}
                    onToggle={() =>
                      setExpanded(expanded === row.model_id ? null : row.model_id)
                    }
                    onAction={(action) =>
                      transition(
                        `${action}:${row.model_id}`,
                        `${action[0].toUpperCase()}${action.slice(1)}`,
                        () =>
                          action === "validate"
                            ? api.registryValidate(row.model_id)
                            : action === "activate"
                              ? api.registryActivate(row.model_id)
                              : api.registryRetire(row.model_id),
                      )
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {rows.map((row) =>
          expanded === row.model_id ? (
            <div key={`${row.model_id}-checks`} className="expanded-checks">
              <h3 className="section-label">
                Validation checks — {row.model_id}
              </h3>
              <Checks row={row} />
            </div>
          ) : null,
        )}
        {!manage && rows.length > 0 && (
          <p className="note">
            Transitions (validate / activate / retire / rollback) require the
            “model:manage” permission.
          </p>
        )}
      </section>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Compare two models</h2>
          {rows.length < 2 ? (
            <p className="note">Needs at least two registry models.</p>
          ) : (
            <form className="controls" onSubmit={compare}>
              <label>
                A
                <select value={compareA} onChange={(e) => setCompareA(e.target.value)}>
                  <option value="">pick…</option>
                  {rows.map((row) => (
                    <option key={row.model_id} value={row.model_id}>
                      {row.model_id} ({row.status})
                    </option>
                  ))}
                </select>
              </label>
              <label>
                B
                <select value={compareB} onChange={(e) => setCompareB(e.target.value)}>
                  <option value="">pick…</option>
                  {rows.map((row) => (
                    <option key={row.model_id} value={row.model_id}>
                      {row.model_id} ({row.status})
                    </option>
                  ))}
                </select>
              </label>
              <button type="submit" disabled={!compareA || !compareB}>
                Compare
              </button>
            </form>
          )}
          {compareError && <ErrorBox message={compareError} />}
          {diff && (
            <div className="kv-list" style={{ marginTop: 8 }}>
              <KV k="same artifact" verdict={diff.diff.same_artifact ? "ok" : "bad"}>
                {diff.diff.same_artifact ? "yes" : "no"}
              </KV>
              <KV
                k="same feature schema"
                verdict={diff.diff.same_feature_schema ? "ok" : "bad"}
              >
                {diff.diff.same_feature_schema ? "yes" : "no"}
              </KV>
              <KV k="status">
                {diff.diff.status?.a} → {diff.diff.status?.b}
              </KV>
              <KV k="training rows">
                {formatNum(diff.diff.n_train?.a ?? null)} vs{" "}
                {formatNum(diff.diff.n_train?.b ?? null)}
                {diff.diff.n_train?.delta != null &&
                  ` (Δ ${diff.diff.n_train.delta > 0 ? "+" : ""}${diff.diff.n_train.delta})`}
              </KV>
              <KV k="created">
                {formatTs(diff.a.created_at)} vs {formatTs(diff.b.created_at)}
              </KV>
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Train a model</h2>
          {!manage ? (
            <p className="note">
              Training requires the “model:manage” permission — an administrator
              can upgrade your role.
            </p>
          ) : (
            <form className="controls" onSubmit={train}>
              <label>
                Capture (benign baseline)
                <select
                  value={captureId}
                  onChange={(e) => setCaptureId(e.target.value)}
                  required
                >
                  <option value="">pick a COMPLETED capture…</option>
                  {(captures.data?.items ?? [])
                    .filter((capture) => capture.status === "COMPLETED")
                    .map((capture) => (
                      <option key={capture.capture_id} value={capture.capture_id}>
                        #{capture.capture_id} {capture.original_name ?? ""} (
                        {formatNum(capture.flows)} flows)
                      </option>
                    ))}
                </select>
              </label>
              <label>
                Contamination
                <input
                  type="number"
                  step="0.005"
                  min={0.001}
                  max={0.499}
                  value={contamination}
                  onChange={(e) => setContamination(e.target.value)}
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={activate}
                  onChange={(e) => setActivate(e.target.checked)}
                />
                Activate after validation (audited swap)
              </label>
              <button type="submit" disabled={busyKey === "train" || !captureId}>
                {busyKey === "train"
                  ? "Training…"
                  : activate
                    ? "Train & activate"
                    : "Train as candidate"}
              </button>
            </form>
          )}
          {trainResult && <p className="note ok-text">{trainResult}</p>}
        </section>
      </div>

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Drift vs training baseline</h2>
          {!can("investigate") && (
            <p className="note">Drift analysis requires the “investigate” permission.</p>
          )}
          {can("investigate") && drift.loading && !drift.data && (
            <Loading label="Measuring PSI…" />
          )}
          {can("investigate") && drift.error && (
            <ErrorBox message={drift.error} onRetry={drift.reload} />
          )}
          {can("investigate") && drift.data && !drift.data.available && (
            <Empty
              message="Drift not measurable yet"
              hint={drift.data.reason ?? "Score some traffic first."}
            />
          )}
          {can("investigate") && drift.data?.available && (
            <>
              <KV k="level">
                <span
                  className={`badge ${
                    drift.data.level === "stable"
                      ? "state-healthy"
                      : drift.data.level === "moderate"
                        ? "state-degraded"
                        : "state-unavailable"
                  }`}
                >
                  {drift.data.level}
                </span>
              </KV>
              <KV k="overall PSI">{drift.data.psi}</KV>
              <KV k="window">
                {formatNum(drift.data.n)} scored flow(s)
              </KV>
              <div className="table-wrap" style={{ marginTop: 8 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Feature</th>
                      <th>PSI</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(drift.data.features ?? []).map((feature) => (
                      <tr key={feature.feature}>
                        <td>{feature.feature}</td>
                        <td>
                          {feature.constant ? (
                            <span className="dim">constant (skipped)</span>
                          ) : (
                            <span
                              className={`badge ${
                                feature.psi > 0.25
                                  ? "state-unavailable"
                                  : feature.psi > 0.1
                                    ? "state-degraded"
                                    : "state-healthy"
                              }`}
                            >
                              {feature.psi}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Training lineage</h2>
          {runs.loading && !runs.data && <Loading label="Loading runs…" />}
          {runs.error && <ErrorBox message={runs.error} onRetry={runs.reload} />}
          {runs.data && runs.data.items.length === 0 && (
            <Empty
              message="No training runs recorded"
              hint="Train on a capture to build lineage."
            />
          )}
          {runs.data && runs.data.items.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Trained</th>
                    <th>PCAP</th>
                    <th>Rows</th>
                    <th>Contam.</th>
                    <th>Metrics</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.data.items.map((run) => {
                    const metrics = parseJson<Record<string, unknown>>(run.metrics);
                    const metricText = Object.entries(metrics)
                      .filter(([, value]) => typeof value !== "object")
                      .slice(0, 4)
                      .map(([key, value]) => `${key}=${String(value)}`)
                      .join(" · ");
                    return (
                      <tr key={run.id}>
                        <td className="dim" title={formatTs(run.trained_at)}>
                          {relTime(run.trained_at)}
                        </td>
                        <td className="mono">{run.pcap ?? "—"}</td>
                        <td>{formatNum(run.n_train)}</td>
                        <td>{run.contamination ?? "—"}</td>
                        <td className="dim mono">{metricText || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {!manage && (
        <section className="panel" style={{ marginTop: 16 }}>
          <h2>Read-only role</h2>
          <p className="note">
            You can inspect the active model, registry states, drift and
            lineage. Training and lifecycle transitions (validate / activate /
            retire / rollback) require the “model:manage” permission.
          </p>
        </section>
      )}
    </>
  );
}

function Row({
  row,
  manage,
  busy,
  busyKey,
  expanded,
  onToggle,
  onAction,
}: {
  row: RegistryRow;
  manage: boolean;
  busy: boolean;
  busyKey: string | null;
  expanded: boolean;
  onToggle: () => void;
  onAction: (action: "validate" | "activate" | "retire") => void;
}) {
  const actions = actionsFor(row);
  return (
    <>
      <tr>
        <td className="mono">
          <button className="linkish" onClick={onToggle} title="Toggle validation checks">
            {row.model_id}
          </button>
        </td>
        <td>
          <span className={`badge ${registryStatusClass(row.status)}`}>
            {row.status}
          </span>
        </td>
        <td className="dim">{row.source}</td>
        <td>{formatNum(row.n_train)}</td>
        <td>{row.threshold ?? "—"}</td>
        <td className="mono dim" title={row.artifact_sha256}>
          {shortHash(row.artifact_sha256, 8)}
        </td>
        <td className="dim" title={formatTs(row.created_at)}>
          {relTime(row.created_at)}
        </td>
        <td title={row.last_activated_at ? formatTs(row.last_activated_at) : undefined}>
          {row.activated_count}
        </td>
        <td>
          {actions.length === 0 ? (
            <span className="dim">{row.status === "FAILED" ? "failed" : "—"}</span>
          ) : (
            actions.map((action) => (
              <button
                key={action}
                className="ghost small"
                disabled={!manage || busy}
                title={manage ? `${action} ${row.model_id}` : "Requires model:manage"}
                onClick={() => onAction(action as "validate" | "activate" | "retire")}
                style={{ marginRight: 6 }}
              >
                {busyKey === `${action}:${row.model_id}` ? "…" : action}
              </button>
            ))
          )}
          {expanded && row.status === "FAILED" && row.error && (
            <span className="dim"> {row.error}</span>
          )}
        </td>
      </tr>
    </>
  );
}
