import { useId, type CSSProperties, type ReactNode } from "react";
import { Viewfinder } from "./display";

/* Decorative SVG/CSS art. All aria-hidden; all static under prefers-reduced-motion. */

/** Faint dot-matrix grid that fades out downwards (place inside a positioned parent). */
export function DotGridBackground({ opacity = 0.07, pitch = 10, fade = "70%" }: { opacity?: number; pitch?: number; fade?: string }) {
  return (
    <span
      className="sx-dotgrid"
      aria-hidden
      style={{ "--dot-a": opacity, "--dot-pitch": `${pitch}px`, "--dot-fade": fade } as CSSProperties}
    />
  );
}

/** Spectra's mark: a prism (diamond) that flow lines enter and a spectrum leaves. Original artwork. */
export function SpectraMark({ size = 40, title }: { size?: number; title?: string }) {
  const id = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" role={title ? "img" : undefined} aria-hidden={title ? undefined : true} aria-label={title}>
      <defs>
        <linearGradient id={`${id}-g`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#95C1F0" />
          <stop offset="0.55" stopColor="#2A66CC" />
          <stop offset="1" stopColor="#15418A" />
        </linearGradient>
      </defs>
      <path d="M24 4 42 24 24 44 6 24Z" fill="none" stroke={`url(#${id}-g)`} strokeWidth="2" />
      <path d="M24 12 34 24 24 36 14 24Z" fill={`url(#${id}-g)`} opacity="0.9" />
      <path d="M24 4v8M24 36v8" stroke="#95C1F0" strokeWidth="1" opacity="0.6" />
    </svg>
  );
}

export function Wordmark({ size = 16 }: { size?: number }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--text-1)" }}>
      <SpectraMark size={size * 1.75} />
      <span style={{ fontSize: size, fontWeight: 500, letterSpacing: "0.22em" }}>SPECTRA</span>
    </span>
  );
}

/**
 * The light beam: thin vertical "flow lines" (packets) rising into the mark,
 * with a soft bloom. Deterministic positions, so it renders the same every time.
 */
export function LightBeam({ width = 160, height = 240, lines = 22 }: { width?: number; height?: number; lines?: number }) {
  const id = useId();
  const cx = width / 2;
  const parts = Array.from({ length: lines }, (_, i) => {
    const spread = ((i * 37) % 100) / 100 - 0.5; // -0.5..0.5, deterministic
    const x = cx + spread * width * 0.42 * (1 - (i % 3) * 0.25);
    const len = 10 + ((i * 13) % 26);
    const d = 3 + ((i * 7) % 5);
    const delay = -((i * 0.37) % d);
    return { x, len, d, delay, o: 0.35 + ((i * 11) % 60) / 100 };
  });
  return (
    <svg className="sx-beam" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden>
      <defs>
        <linearGradient id={`${id}-core`} x1="0" y1="1" x2="0" y2="0">
          <stop offset="0" stopColor="#2A66CC" stopOpacity="0" />
          <stop offset="0.6" stopColor="#5DA2F7" stopOpacity="0.55" />
          <stop offset="1" stopColor="#95C1F0" stopOpacity="0.95" />
        </linearGradient>
        <radialGradient id={`${id}-bloom`} cx="0.5" cy="0" r="0.6">
          <stop offset="0" stopColor="#2A66CC" stopOpacity="0.45" />
          <stop offset="1" stopColor="#2A66CC" stopOpacity="0" />
        </radialGradient>
        <filter id={`${id}-blur`} x="-50%" y="-10%" width="200%" height="120%">
          <feGaussianBlur stdDeviation="6" />
        </filter>
      </defs>
      <ellipse cx={cx} cy={0} rx={width * 0.5} ry={height * 0.5} fill={`url(#${id}-bloom)`} />
      <rect x={cx - 6} y={0} width={12} height={height} fill={`url(#${id}-core)`} filter={`url(#${id}-blur)`} />
      <rect x={cx - 0.75} y={0} width={1.5} height={height} fill={`url(#${id}-core)`} />
      {parts.map((p, i) => (
        <line
          key={i}
          className="sx-beam-particle"
          x1={p.x}
          x2={p.x}
          y1={height}
          y2={height - p.len}
          stroke="#95C1F0"
          strokeWidth="1"
          strokeOpacity={p.o}
          style={{ "--d": `${p.d}s`, "--delay": `${p.delay}s`, "--rise": `-${height}px` } as CSSProperties}
        />
      ))}
    </svg>
  );
}

/** Radial lines converging through a ring, with a few particles (empty states, "how it works"). */
export function SignalField({ size = 220 }: { size?: number }) {
  const id = useId();
  const c = 100;
  const rays = Array.from({ length: 36 }, (_, i) => {
    const a = (i / 36) * Math.PI * 2;
    return { x: c + Math.cos(a) * 96, y: c + Math.sin(a) * 96, o: 0.12 + ((i * 7) % 10) / 40 };
  });
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" aria-hidden>
      <defs>
        <radialGradient id={`${id}-glow`}>
          <stop offset="0" stopColor="#5DA2F7" stopOpacity="0.5" />
          <stop offset="1" stopColor="#5DA2F7" stopOpacity="0" />
        </radialGradient>
      </defs>
      {rays.map((r, i) => (
        <line key={i} x1={r.x} y1={r.y} x2={c} y2={c} stroke="#5DA2F7" strokeOpacity={r.o} strokeWidth="0.6" />
      ))}
      <circle cx={c} cy={c} r="38" fill={`url(#${id}-glow)`} />
      <circle cx={c} cy={c} r="30" fill="none" stroke="#95C1F0" strokeOpacity="0.7" strokeWidth="1" />
      <circle cx={c} cy={c} r="44" fill="none" stroke="#95C1F0" strokeOpacity="0.18" strokeWidth="1" strokeDasharray="2 4" />
      {[20, 95, 160, 230, 300].map((deg, i) => {
        const a = (deg * Math.PI) / 180;
        const r = 54 + i * 7;
        return <rect key={deg} x={c + Math.cos(a) * r - 1.5} y={c + Math.sin(a) * r - 1.5} width="3" height="3" fill="#95C1F0" opacity="0.8" />;
      })}
      <circle cx={c} cy={c} r="3" fill="#F2F4F8" />
    </svg>
  );
}

/** Layered misty terrain silhouette (landing/login hero). */
export function Terrain({ height = 180 }: { height?: number }) {
  const id = useId();
  return (
    <svg width="100%" height={height} viewBox="0 0 1200 180" preserveAspectRatio="none" aria-hidden style={{ display: "block" }}>
      <defs>
        <linearGradient id={`${id}-haze`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#151A24" stopOpacity="0" />
          <stop offset="1" stopColor="#030407" stopOpacity="1" />
        </linearGradient>
        <filter id={`${id}-soft`}>
          <feGaussianBlur stdDeviation="3" />
        </filter>
      </defs>
      <path d="M0 110 L120 70 L210 96 L330 40 L450 92 L560 58 L700 100 L820 52 L950 88 L1060 62 L1200 98 V180 H0Z" fill="#151A24" filter={`url(#${id}-soft)`} />
      <path d="M0 130 L140 96 L260 122 L400 80 L520 118 L640 92 L780 128 L900 90 L1040 120 L1200 104 V180 H0Z" fill="#0F131B" />
      <path d="M0 152 L180 126 L330 148 L480 120 L620 150 L760 128 L900 154 L1050 130 L1200 148 V180 H0Z" fill="#0B0E14" />
      <rect width="1200" height="180" fill={`url(#${id}-haze)`} />
    </svg>
  );
}

/** Hero focal: the mark in viewfinder brackets with the flow beam rising into it. */
export function HeroFocal({ children }: { children?: ReactNode }) {
  return (
    <div style={{ display: "grid", justifyItems: "center" }}>
      <Viewfinder size={18} padding={18}>
        <div style={{ filter: "drop-shadow(0 0 18px rgba(47,107,255,.55))" }}>
          <SpectraMark size={72} />
        </div>
      </Viewfinder>
      <LightBeam />
      {children}
    </div>
  );
}

/** Graph styling demo: glowing square nodes, thin blue edges, selected node bracketed. */
export function GraphSample({ selected = 2 }: { selected?: number }) {
  const nodes = [
    { x: 40, y: 60 },
    { x: 140, y: 30 },
    { x: 200, y: 110 },
    { x: 90, y: 150 },
    { x: 280, y: 60 },
  ];
  const edges = [
    [0, 1],
    [1, 2],
    [2, 3],
    [0, 3],
    [2, 4],
    [1, 4],
  ];
  const s = nodes[selected];
  return (
    <svg width="320" height="190" viewBox="0 0 320 190" role="img" aria-label="Sample correlation graph, node 3 selected">
      {edges.map(([a, b], i) => (
        <line key={i} className="sx-graph-edge" x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} />
      ))}
      {nodes.map((n, i) => (
        <rect key={i} className="sx-graph-node" x={n.x - 4} y={n.y - 4} width="8" height="8" />
      ))}
      <g stroke="#95C1F0" strokeWidth="1.5" fill="none">
        <path d={`M${s.x - 14} ${s.y - 8}v-6h6M${s.x + 8} ${s.y - 14}h6v6M${s.x + 14} ${s.y + 8}v6h-6M${s.x - 8} ${s.y + 14}h-6v-6`} />
      </g>
    </svg>
  );
}
