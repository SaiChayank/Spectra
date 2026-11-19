import { motion, useReducedMotion, type Variants } from "motion/react";
import type { ReactNode } from "react";
import capabilityExport from "../../contract/fixtures/GET_api_capabilities.json";
import { navigate } from "../lib/router";
import HeroScene, { HeroMark } from "./HeroScene";
import { Badge, Eyebrow, SkewButton, Viewfinder, Wordmark } from "./ui";
import "./landing.css";

/**
 * Public landing. It makes no API calls: every backend route except
 * /api/health needs a session, and a signed-out page must stay silent.
 *
 * The module strip uses only each module's title and maturity status from the
 * generated contract export (frontend/contract/), which are fixed in backend
 * capabilities.py; the contract drift check fails CI if they change without a
 * re-export. Live fields (availability, failures) are not shown.
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
  ["Home", "#top"],
  ["How it works", "#how"],
  ["Modules", "#modules"],
  ["Limitations", "#status"],
];

/* -- motion presets (all disabled by MotionConfig reducedMotion="user" and useReducedMotion) -- */
const rise: Variants = {
  hidden: { opacity: 0, y: 18 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.2, 0.7, 0.2, 1] } },
};
const stagger: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.09, delayChildren: 0.1 } } };

function Reveal({ children, className, delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  return (
    <motion.div className={className} initial="hidden" whileInView="show" viewport={{ once: true, margin: "-80px" }} variants={rise} transition={{ delay }}>
      {children}
    </motion.div>
  );
}

const ICON = {
  capture: <path d="M12 3v12m0 0-4-4m4 4 4-4M4 17v3h16v-3" />,
  flow: <path d="M3 7h13l-3-3M21 17H8l3 3" />,
  score: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 12l4-3" />
    </>
  ),
  alert: <path d="M12 3 2 20h20ZM12 10v4M12 17v.5" />,
  audit: <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6Zm-3 9 2 2 4-4" />,
  honest: (
    <>
      <rect x="4" y="4" width="16" height="16" />
      <path d="M8 12h8M8 8h8M8 16h5" />
    </>
  ),
};

function IconSquare({ name }: { name: keyof typeof ICON }) {
  return (
    <span className="sx-l-icon" aria-hidden>
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
        {ICON[name]}
      </svg>
    </span>
  );
}

const FEATURES: { tag: string; icon: keyof typeof ICON; title: string; body: string; tags: string[] }[] = [
  { tag: "Capture", icon: "capture", title: "Passive capture", body: "Upload a PCAP or listen on an interface. Uploads are rewritten to headers and handshakes only.", tags: ["#PCAP", "#LIVE"] },
  { tag: "Parsing", icon: "flow", title: "Flow metadata", body: "39 features per flow: sizes, timing, direction, and TLS/QUIC handshake fields such as SNI, ALPN, JA3/JA4.", tags: ["#TLS", "#QUIC"] },
  { tag: "Detection", icon: "score", title: "Explained scoring", body: "An isolation forest trained on your own baseline scores each flow against a threshold and lists what moved it.", tags: ["#BASELINE", "#REASONS"] },
  { tag: "Response", icon: "alert", title: "Alerts & incidents", body: "Unusual flows become alerts with their evidence; analysts acknowledge, investigate and resolve them.", tags: ["#TRIAGE", "#EVIDENCE"] },
  { tag: "Integrity", icon: "audit", title: "Audit chain", body: "State changes are attributed and recorded in a hash-chained log with checkpoints and inclusion proofs.", tags: ["#AUDIT", "#PROOFS"] },
  { tag: "Honesty", icon: "honest", title: "Maturity labels", body: "Every module says whether it is real, local, simulated or experimental. Simulations are never sold as controls.", tags: ["#REAL", "#SIMULATED"] },
];

/** Lines converging through a ring, sideways (the "lens" in the reference shots). Original SVG. */
function TunnelLens() {
  const reduce = useReducedMotion() ?? false;
  const lines = Array.from({ length: 26 }, (_, i) => {
    const t = i / 25;
    const yL = 20 + t * 320;
    const yR = 60 + t * 240;
    const bend = (t - 0.5) * 70;
    return { d: `M0 ${yL} C 260 ${yL}, 380 ${180 + bend * 0.4}, 500 ${180 + bend * 0.15} S 760 ${yR}, 1000 ${yR}`, o: 0.18 + (1 - Math.abs(t - 0.5) * 2) * 0.55 };
  });
  const dots = Array.from({ length: 40 }, (_, i) => ({ x: ((i * 97) % 1000) + 0.5, y: 30 + ((i * 53) % 300), r: 0.8 + ((i * 7) % 10) / 6 }));
  return (
    <svg className="sx-lens" viewBox="0 0 1000 360" preserveAspectRatio="xMidYMid slice" aria-hidden>
      <defs>
        <radialGradient id="sx-lens-glow" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor="#5da2f7" stopOpacity="0.55" />
          <stop offset="1" stopColor="#5da2f7" stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect width="1000" height="360" fill="#000" />
      <ellipse cx="500" cy="180" rx="240" ry="150" fill="url(#sx-lens-glow)" />
      {lines.map((l, i) => (
        <path key={i} d={l.d} stroke="#5da2f7" strokeOpacity={l.o} strokeWidth="1" fill="none" className={reduce ? undefined : "sx-lens-line"} style={{ animationDelay: `${-i * 0.27}s` }} />
      ))}
      <ellipse cx="500" cy="180" rx="46" ry="120" fill="none" stroke="#9fd0ff" strokeOpacity="0.85" strokeWidth="1.4" />
      <ellipse cx="500" cy="180" rx="70" ry="150" fill="none" stroke="#9fd0ff" strokeOpacity="0.22" strokeDasharray="2 5" />
      <line x1="0" y1="180" x2="1000" y2="180" stroke="#9fd0ff" strokeOpacity="0.25" />
      <line x1="500" y1="0" x2="500" y2="360" stroke="#9fd0ff" strokeOpacity="0.12" />
      {dots.map((d, i) => (
        <circle key={i} cx={d.x} cy={d.y} r={d.r} fill="#9fd0ff" opacity={0.25 + (i % 5) * 0.12} className={reduce ? undefined : "sx-twinkle"} style={{ animationDelay: `${-i * 0.31}s`, animationDuration: `${2 + (i % 4)}s` }} />
      ))}
      <path d="M496 180h8M500 176v8" stroke="#fff" strokeWidth="1.2" />
    </svg>
  );
}

export default function Landing() {
  const signIn = () => navigate("#/login");
  const reduce = useReducedMotion() ?? false;
  const lines = ["See the flow.", "Never the payload.", <>Act on evi<span className="sx-gold">dence</span>.</>];

  return (
    <div className="sx sx-landing-page">
      <div className="sx-landing-frame" id="top">
        {/* -- hero ------------------------------------------------------------------ */}
        <section className="sx-hero" aria-labelledby="hero-title">
          <HeroScene
            focal={
              <Viewfinder size={16} padding={22}>
                <HeroMark size={84} />
              </Viewfinder>
            }
          />

          <motion.header className="sx-landing-head" initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
            <Wordmark size={17} />
            <nav aria-label="Landing sections" className="sx-landing-nav">
              {NAV.map(([label, href], i) => (
                <a key={href} href={href} className="sx-tab sx-landing-navlink" aria-current={i === 0 ? "page" : undefined}>
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
          </motion.header>

          <div className="sx-hero-copy">
            <motion.div className="sx-hero-left" initial="hidden" animate="show" variants={stagger}>
              <motion.div variants={rise}>
                <Eyebrow>Metadata-only detection</Eyebrow>
              </motion.div>
              <h1 id="hero-title" className="sx-display">
                {lines.map((l, i) => (
                  <motion.span key={i} className="sx-hero-line" variants={rise}>
                    {l}
                  </motion.span>
                ))}
              </h1>
            </motion.div>
            <motion.div className="sx-hero-right" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.45 }}>
              <p>
                Spectra turns flow statistics and TLS/QUIC handshake fields into explained alerts, so teams can spot traffic that is
                unusual for their network without ever decrypting it.
              </p>
              <div className="sx-hero-actions">
                <SkewButton icon="⚡" onClick={signIn}>
                  Sign in
                </SkewButton>
                <a href="#how" className="sx-btn sx-btn--secondary sx-hero-link">
                  How it works <span aria-hidden>↗</span>
                </a>
              </div>
            </motion.div>
          </div>
        </section>

        {/* -- module strip (the "trusted ecosystem" row, made honest) ------------------ */}
        <section className="sx-capstrip" id="modules" aria-labelledby="modules-title">
          <p id="modules-title" className="sx-capstrip-title">
            Module maturity in this build
          </p>
          <div className="sx-marquee" data-still={reduce || undefined}>
            <ul className="sx-marquee-track">
              {[...MODULES, ...MODULES].map((m, i) => (
                <li key={i} className="sx-captile" aria-hidden={i >= MODULES.length || undefined}>
                  <span className="sx-captile-name">{m.title}</span>
                  <Badge tone={TONE[m.status] ?? "neutral"}>{m.status.replace("_", " ")}</Badge>
                </li>
              ))}
            </ul>
          </div>
          <p className="sx-hint sx-capstrip-note">
            REAL runs on real data; LOCAL runs only on this machine; SIMULATED is a software stand-in, not a production control. No module
            is hardware-backed, and none changes a score: modules add evidence only.
          </p>
        </section>

        {/* -- two big cards ------------------------------------------------------------------ */}
        <section className="sx-landing-section" id="how" aria-labelledby="how-title">
          <Reveal>
            <h2 id="how-title" className="sx-section-title">
              Built to turn metadata
              <br />
              into evidence
            </h2>
          </Reveal>
          <div className="sx-duo">
            <Reveal className="sx-duo-card sx-duo-card--wide">
              <div className="sx-duo-art" aria-hidden>
                <div className="sx-duo-art-glow" />
                <HeroMark size={110} />
              </div>
              <div className="sx-duo-body">
                <Eyebrow>The Spectra platform</Eyebrow>
                <h3 className="sx-duo-title">One console for metadata-only detection</h3>
                <p>Capture, parse, score, triage and audit in one place, on your own machine, with your own baseline.</p>
                <dl className="sx-duo-stats">
                  <div>
                    <dt>Per flow</dt>
                    <dd>39 features</dd>
                  </div>
                  <div>
                    <dt>Payload</dt>
                    <dd>Never decrypted</dd>
                  </div>
                </dl>
              </div>
            </Reveal>
            <Reveal className="sx-duo-card sx-duo-card--glow" delay={0.1}>
              <div className="sx-duo-body">
                <Eyebrow>Our focus</Eyebrow>
                <h3 className="sx-duo-title">Clarity on every flagged flow</h3>
                <p>Each alert carries its score against the threshold, the signals for and against it, and why it got its severity.</p>
              </div>
              <div className="sx-duo-chip">
                <span className="sx-l-icon" aria-hidden>
                  ◆
                </span>
                Detect, explain, decide
              </div>
            </Reveal>
          </div>
        </section>

        {/* -- six-card grid -------------------------------------------------------------------- */}
        <section className="sx-landing-section" aria-labelledby="grid-title">
          <Reveal className="sx-grid-head">
            <h2 id="grid-title" className="sx-section-title">
              Secure by design,
              <br />
              honest by default
            </h2>
            <a className="sx-btn sx-btn--secondary sx-btn--sm sx-hero-link" href={DOCS} rel="noreferrer">
              Read the docs <span aria-hidden>↗</span>
            </a>
          </Reveal>
          <motion.div className="sx-six" initial="hidden" whileInView="show" viewport={{ once: true, margin: "-60px" }} variants={stagger}>
            {FEATURES.map((f, i) => (
              <motion.article key={f.title} className="sx-six-card" variants={rise} whileHover={reduce ? undefined : { y: -4 }}>
                <div className="sx-six-top">
                  <Eyebrow>{f.tag}</Eyebrow>
                  <IconSquare name={f.icon} />
                </div>
                <span className="sx-index">{String(i + 1).padStart(2, "0")}</span>
                <h3 className="sx-six-title">{f.title}</h3>
                <p className="sx-six-body">{f.body}</p>
                <p className="sx-six-tags">{f.tags.join(" · ")}</p>
              </motion.article>
            ))}
          </motion.div>
        </section>

        {/* -- lens section ------------------------------------------------------------------------ */}
        <section className="sx-landing-section sx-lens-section" aria-labelledby="never-title">
          <Reveal className="sx-lens-frame">
            <div className="sx-lens-callout">
              <Eyebrow>Why metadata only</Eyebrow>
              <p>
                SPECTRA reads only what a handshake shows in the clear. It turns that into evidence an analyst can check, without ever
                touching what people send.
              </p>
            </div>
            <TunnelLens />
          </Reveal>
          <Reveal className="sx-never-copy">
            <h2 id="never-title" className="sx-section-title" style={{ textAlign: "center" }}>
              What it never does
            </h2>
            <ul className="sx-never-list">
              <li>
                <strong>No decryption.</strong> No keys, no man-in-the-middle.
              </li>
              <li>
                <strong>No payload storage.</strong> Other payload bytes are zeroed on upload.
              </li>
              <li>
                <strong>Passive capture.</strong> It listens; it never blocks, injects or modifies traffic.
              </li>
            </ul>
          </Reveal>
        </section>

        {/* -- detector status (honest) ------------------------------------------------------------------ */}
        <section className="sx-landing-section" id="status" aria-labelledby="status-title">
          <Reveal className="sx-card sx-crosshair sx-status-card">
            <div style={{ display: "grid", gap: 10 }}>
              <Eyebrow>Detector status</Eyebrow>
              <h2 id="status-title" className="sx-section-title" style={{ fontSize: "clamp(24px,3vw,32px)" }}>
                Not a reliable attack detector yet
              </h2>
              <p>
                On three public datasets the detector flagged almost none of the attacks at its default threshold (for example 0 of 98,700
                bot flows in CSE-CIC-IDS2018), and on 72 hours of one benign laptop it still flagged about 1 % of flows. Treat a flagged
                flow as &ldquo;unusual for this network, worth a look&rdquo;, not as proof of an attack.
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
          </Reveal>
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
