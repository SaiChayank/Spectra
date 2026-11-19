import capabilityExport from "../../contract/fixtures/GET_api_capabilities.json";
import { navigate } from "../lib/router";
import {
  Badge,
  CrosshairCard,
  DotGridBackground,
  Eyebrow,
  HeroFocal,
  SignalField,
  SkewButton,
  Terrain,
  Wordmark,
} from "./ui";
import "./landing.css";

/**
 * Public landing. It makes no API calls: every backend route except
 * /api/health needs a session, and a signed-out page must stay silent.
 *
 * The capability strip uses only each module's title and maturity status
 * from the generated contract export (frontend/contract/), which are fixed in
 * backend capabilities.py; the contract drift check fails CI if they change
 * without a re-export. Live fields (availability, failures) are not shown.
 */

type Maturity = "REAL" | "LOCAL" | "SIMULATED" | "EXPERIMENTAL" | "HARDWARE_BACKED" | "UNAVAILABLE";

const MODULES = Object.values(
  (capabilityExport as { body: { modules: Record<string, { title: string; status: Maturity }> } }).body.modules,
).map(({ title, status }) => ({ title, status }));

const TONE: Record<Maturity, "ok" | "blue" | "neutral" | "warn"> = {
  REAL: "ok",
  LOCAL: "blue",
  SIMULATED: "neutral",
  EXPERIMENTAL: "warn",
  HARDWARE_BACKED: "ok",
  UNAVAILABLE: "neutral",
};

const DOCS = "https://github.com/SaiChayank/Spectra/tree/main/docs";
const LIMITATIONS = "https://github.com/SaiChayank/Spectra/blob/main/docs/limitations.md";
const EVALUATION = "https://github.com/SaiChayank/Spectra/blob/main/docs/evaluation-report.md";

const NAV: [string, string][] = [
  ["Overview", "#top"],
  ["How it works", "#how"],
  ["Modules", "#modules"],
  ["Limitations", "#status"],
];

export default function Landing() {
  const signIn = () => navigate("#/login");
  return (
    <div className="sx sx-landing-page">
      <div className="sx-landing-frame" id="top">
        {/* -- header ----------------------------------------------------------- */}
        <header className="sx-landing-head">
          <Wordmark size={15} />
          <nav aria-label="Landing sections" className="sx-landing-nav">
            {NAV.map(([label, href]) => (
              <a key={href} href={href} className="sx-tab sx-landing-navlink">
                {label}
              </a>
            ))}
            <a href={DOCS} className="sx-tab sx-landing-navlink" rel="noreferrer">
              Docs
            </a>
          </nav>
          <SkewButton size="sm" onClick={signIn}>
            Sign in
          </SkewButton>
        </header>

        {/* -- hero ---------------------------------------------------------------- */}
        <section className="sx-hero" aria-labelledby="hero-title">
          <div className="sx-hero-sky" aria-hidden>
            <DotGridBackground opacity={0.1} pitch={11} fade="65%" />
            <span className="sx-hero-mist" />
          </div>
          <div className="sx-hero-terrain" aria-hidden>
            <Terrain height={260} />
          </div>
          <div className="sx-hero-focal" aria-hidden>
            <HeroFocal beam={330} />
          </div>

          <div className="sx-hero-copy">
            <div className="sx-hero-left">
              <Eyebrow>Metadata-only detection</Eyebrow>
              <h1 id="hero-title" className="sx-display">
                See the flow.
                <br />
                Never the payload.
                <br />
                Act on <span className="sx-gold">evidence</span>.
              </h1>
            </div>
            <div className="sx-hero-right">
              <p>
                Spectra reads flow statistics and TLS/QUIC handshake fields (server names, versions, JA3/JA4 fingerprints, timing)
                to flag traffic that is unusual for your network, with the reasons attached. Payload is never decrypted, stored or
                shown.
              </p>
              <div className="sx-hero-actions">
                <SkewButton icon="⚡" onClick={signIn}>
                  Sign in
                </SkewButton>
                <a href="#how" className="sx-btn sx-btn--secondary sx-hero-link">
                  How it works <span aria-hidden>↗</span>
                </a>
              </div>
            </div>
          </div>
        </section>

        {/* -- capability strip ----------------------------------------------------------- */}
        <section className="sx-landing-section sx-capstrip" id="modules" aria-labelledby="modules-title">
          <p id="modules-title" className="sx-eyebrow sx-capstrip-title">
            Module maturity in this build
          </p>
          <ul className="sx-capstrip-tiles">
            {MODULES.map((m) => (
              <li key={m.title} className="sx-captile">
                <span className="sx-captile-name">{m.title}</span>
                <Badge tone={TONE[m.status] ?? "neutral"}>{m.status.replace("_", " ")}</Badge>
              </li>
            ))}
          </ul>
          <p className="sx-hint sx-capstrip-note">
            REAL runs on real data; LOCAL runs only on this machine; SIMULATED is a software stand-in, not a production control. No
            module is hardware-backed, and none changes a score: modules add evidence only.
          </p>
        </section>

        {/* -- how it works ------------------------------------------------------------------- */}
        <section className="sx-landing-section" id="how" aria-labelledby="how-title">
          <h2 id="how-title" className="sx-section-title">
            Built to turn metadata
            <br />
            into evidence
          </h2>
          <div className="sx-feature-grid">
            <CrosshairCard index="01" icon="⇣" title="Capture">
              Upload a PCAP or capture live from an interface. Uploaded captures are rewritten to headers and handshakes only.
            </CrosshairCard>
            <CrosshairCard index="02" icon="≋" title="Flow metadata">
              39 features per flow: sizes, timing, direction, and TLS/QUIC handshake fields such as SNI, ALPN and JA3/JA4.
            </CrosshairCard>
            <CrosshairCard index="03" icon="◎" title="Explained scoring">
              An isolation forest trained on your own baseline scores each flow 0-100 against a threshold, and lists the features
              that moved it.
            </CrosshairCard>
            <CrosshairCard index="04" icon="⛨" title="Incidents and audit">
              Alerts group into incidents that analysts acknowledge, investigate and resolve. State changes are attributed and
              recorded in a hash-chained audit log.
            </CrosshairCard>
          </div>
        </section>

        {/* -- what it never does ----------------------------------------------------------------- */}
        <section className="sx-landing-section sx-never" aria-labelledby="never-title">
          <div className="sx-never-art" aria-hidden>
            <SignalField size={300} />
          </div>
          <div className="sx-never-copy">
            <Eyebrow>Privacy by design</Eyebrow>
            <h2 id="never-title" className="sx-section-title">
              What it never does
            </h2>
            <ul className="sx-never-list">
              <li>
                <strong>No decryption.</strong> Spectra has no keys and no man-in-the-middle; it reads what the handshake shows in the
                clear.
              </li>
              <li>
                <strong>No payload storage.</strong> Uploaded captures keep headers, lengths and handshake records; other payload bytes
                are zeroed on arrival.
              </li>
              <li>
                <strong>Passive capture.</strong> It listens. It does not block, inject or modify traffic.
              </li>
            </ul>
          </div>
        </section>

        {/* -- detector status (honest) --------------------------------------------------------------- */}
        <section className="sx-landing-section" id="status" aria-labelledby="status-title">
          <div className="sx-card sx-crosshair sx-status-card">
            <div style={{ display: "grid", gap: 10 }}>
              <Eyebrow>Detector status</Eyebrow>
              <h2 id="status-title" className="sx-section-title" style={{ fontSize: "clamp(24px,3vw,32px)" }}>
                Not a reliable attack detector yet
              </h2>
              <p>
                On three public datasets the detector flagged almost none of the attacks at its default threshold (for example 0 of
                98,700 bot flows in CSE-CIC-IDS2018), and on 72 hours of one benign laptop it still flagged about 1 % of flows. Treat a
                flagged flow as &ldquo;unusual for this network, worth a look&rdquo;, not as proof of an attack.
              </p>
              <p className="sx-hint">Source: evaluation report §14 and §20 (2026-11-07 and 2026-11-18).</p>
            </div>
            <div className="sx-status-actions">
              <a className="sx-btn sx-btn--ghost sx-hero-link" href={LIMITATIONS} rel="noreferrer">
                Read the limitations <span aria-hidden>↗</span>
              </a>
              <a className="sx-btn sx-btn--ghost sx-hero-link" href={EVALUATION} rel="noreferrer">
                Evaluation report <span aria-hidden>↗</span>
              </a>
            </div>
          </div>
        </section>

        <footer className="sx-landing-foot">
          <Wordmark size={12} />
          <p className="sx-hint">
            Apache-2.0 · local accounts only · first run: the initial admin password is in <code>backend/data/admin_bootstrap.txt</code>{" "}
            (or set <code>SPECTRA_ADMIN_PASSWORD</code>).
          </p>
        </footer>
      </div>
    </div>
  );
}
