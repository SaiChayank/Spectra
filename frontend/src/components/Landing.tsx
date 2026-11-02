import { navigate } from "../lib/router";

/**
 * Public landing — no API calls (every backend route requires a session,
 * and an unauthenticated page must stay silent, not error). The sign-in
 * button routes to `#/login`, where LoginPanel collects credentials.
 */
export default function Landing() {
  return (
    <div className="landing">
      <header className="landing-hero">
        <p className="landing-kicker">encrypted traffic threat detection</p>
        <h1 className="landing-title">SPECTRA</h1>
        <p className="landing-lede">
          Metadata-only network detection for SOC teams. SPECTRA scores flow
          statistics and TLS/QUIC handshake structure — SNI, ALPN, protocol
          versions, cipher lists, JA3/JA4 fingerprints and timing — and never
          decrypts, stores, or displays payload contents.
        </p>
        <div className="landing-cta">
          <button onClick={() => navigate("#/login")}>Sign in to the console</button>
          <span className="landing-cta-note">
            local accounts · role-based access · audit-chained actions
          </span>
        </div>
      </header>

      <section className="landing-grid">
        <article className="panel landing-card">
          <h2>Detect</h2>
          <p className="note">
            Isolation-forest scoring over flow metadata with explainable
            reasons per detection, plus a threat classifier that turns raw
            anomalies into confidence-scored, severity-ranked alerts.
          </p>
        </article>
        <article className="panel landing-card">
          <h2>Investigate</h2>
          <p className="note">
            Incidents, correlation graph, related flows, TLS evidence, module
            contributions and audit references — one bounded bundle per
            incident, with state changes attributed and hash-chained.
          </p>
        </article>
        <article className="panel landing-card">
          <h2>Prove</h2>
          <p className="note">
            A model registry with validation gates and audited
            activate/rollback, integrity-verifiable audit trails, capability
            honesty (REAL / LOCAL / SIMULATED badges), and live subsystem
            health.
          </p>
        </article>
      </section>

      <p className="note landing-foot">
        First run: the initial admin password is written to{" "}
        <code>backend/data/admin_bootstrap.txt</code>, or set{" "}
        <code>SPECTRA_ADMIN_PASSWORD</code> before starting the server.
      </p>
    </div>
  );
}
