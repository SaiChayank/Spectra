import BioPanel from "../components/BioPanel";
import CapabilityStrip from "../components/CapabilityStrip";
import EdgePanel from "../components/EdgePanel";
import TeePanel from "../components/TeePanel";
import { ErrorBox, Loading, PageHeader } from "../components/states";
import { api, type CapabilityModule, type CapabilityReport } from "../lib/api";
import { maturityClass } from "../lib/format";
import { useFetch } from "../lib/useFetch";

interface Props {
  can: (permission: string) => boolean;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}

function availabilityDot(module: CapabilityModule) {
  if (module.available === true) return "up";
  if (module.available === false) return "down";
  return "unknown";
}

/**
 * Modules: the honesty layer — per-module maturity badges (REAL / LOCAL /
 * SIMULATED / EXPERIMENTAL), live availability and contracts, plus the
 * interactive bio / TEE / edge consoles where those modules expose actions.
 */
export default function ModulesPage({ can, onError, onNotice }: Props) {
  const report = useFetch<CapabilityReport>(() => api.capabilities(), [], {
    intervalMs: 30000,
  });
  const canRun = can("investigate");
  const canConfig = can("config:manage");
  const entries = Object.entries(report.data?.modules ?? {});

  return (
    <>
      <PageHeader
        title="Modules"
        subtitle="What each module actually is (and is not) — maturity, availability and its data contract."
        actions={
          <button className="ghost" onClick={report.reload}>
            Re-probe
          </button>
        }
      />

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Scoring policy</h2>
        {report.data ? (
          <p className="note">{report.data.scoring_policy}</p>
        ) : (
          <Loading label="Loading capabilities…" />
        )}
        {report.error && <ErrorBox message={report.error} onRetry={report.reload} />}
        <CapabilityStrip showPolicy />
      </section>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Module inventory</h2>
        {report.loading && !report.data && <Loading label="Loading modules…" />}
        {entries.length > 0 && (
          <div className="module-grid">
            {entries.map(([key, module]) => (
              <article className="module-card" key={key}>
                <header className="module-card-head">
                  <span className={`cap-badge ${maturityClass(module.status)}`}>
                    <span
                      className={`cap-dot ${availabilityDot(module)}`}
                      title={
                        module.available === null
                          ? "not probed"
                          : module.available
                            ? "available now"
                            : "unavailable now"
                      }
                    />
                    <span className="cap-status">{module.status}</span>
                  </span>
                  <strong>{module.title}</strong>
                  <span className="mono dim">{key}</span>
                </header>
                <p className="note">{module.note}</p>
                <dl className="module-contract">
                  <dt>consumes</dt>
                  <dd>{module.consumes}</dd>
                  <dt>produces</dt>
                  <dd>{module.produces}</dd>
                </dl>
                <div className="module-badges">
                  {module.hardware_backed && (
                    <span className="badge low">hardware-backed</span>
                  )}
                  {module.evidence_only && <span className="badge low">evidence only</span>}
                  {module.affects_alert_scoring && (
                    <span className="badge mid">affects scoring</span>
                  )}
                  {module.failures != null && module.failures > 0 && (
                    <span className="badge high">{module.failures} failure(s)</span>
                  )}
                </div>
                {(module.detail || module.failure) && (
                  <p className="note dim">
                    {module.detail ?? module.failure}
                  </p>
                )}
              </article>
            ))}
          </div>
        )}
        {report.data && (
          <div className="kv-list" style={{ marginTop: 10 }}>
            {Object.entries(report.data.definitions).map(([status, definition]) => (
              <div className="kv" key={status}>
                <span className={`k cap-status ${status.toLowerCase()}`}>{status}</span>
                <span className="v dim">{definition}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <BioPanel onError={onError} />
      <TeePanel canRun={canRun} onError={onError} onNotice={onNotice} />
      <EdgePanel
        canRun={canRun}
        canConfig={canConfig}
        onError={onError}
        onNotice={onNotice}
      />
    </>
  );
}
