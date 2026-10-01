import CapabilityStrip from "../components/CapabilityStrip";
import SystemHealthPanel from "../components/SystemHealthPanel";
import { KV, PageHeader } from "../components/states";

interface Props {
  /** WebSocket session state from useEvents (App owns the socket). */
  connected: boolean;
}

/**
 * System: the health layer — overall rollup, per-subsystem component
 * health, queue/drop/latency metrics and live capability status.
 * SystemHealthPanel fetches (and can re-fetch) /api/health/system itself.
 */
export default function SystemPage({ connected }: Props) {
  return (
    <>
      <PageHeader
        title="System"
        subtitle="Component health, pipeline pressure and live capability status."
        actions={
          <span className={`pill ${connected ? "ws" : ""}`}>
            <span className="dot" />
            {connected ? "event stream live" : "event stream reconnecting"}
          </span>
        }
      />

      <SystemHealthPanel />

      <section className="panel" style={{ marginTop: 16 }}>
        <h2>Capability status</h2>
        <KV k="meaning">
          REAL = genuinely implemented · LOCAL = runs in-process · SIMULATED =
          designed non-real · EXPERIMENTAL = best-effort
        </KV>
        <CapabilityStrip showPolicy />
      </section>
    </>
  );
}
