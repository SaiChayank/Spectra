import { motion, useMotionValue, useReducedMotion, useSpring, useTransform, type MotionValue } from "motion/react";
import { useEffect, useId, type ReactNode } from "react";

/**
 * Landing hero scene, drawn from scratch (no photos): a dark misty sky with a
 * dot grid, two mountain masses framing a chasm, a lit ledge and a waterfall
 * of blue light (flows streaming down), sparks at the lip, and the mark held
 * in viewfinder brackets above it. Layers drift with the pointer (parallax);
 * everything is static under prefers-reduced-motion.
 */

const W = 1440;
const H = 900;
const CX = 720; // chasm centre
const LIP = 560; // ledge height where the light falls

/** Deterministic pseudo-random so the scene renders identically every time. */
function rand(i: number) {
  const x = Math.sin(i * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

function useParallax(depth: number, x: MotionValue<number>, y: MotionValue<number>) {
  const tx = useTransform(x, (v) => v * depth);
  const ty = useTransform(y, (v) => v * depth * 0.6);
  return { x: tx, y: ty };
}

/**
 * Jagged ridgeline by deterministic midpoint displacement between control
 * points, closed down to the bottom of the scene. Same output every render.
 */
function ridge(points: [number, number][], rough: number, seed: number, close: "left" | "right"): string {
  let pts = points;
  let amp = rough;
  for (let level = 0; level < 6; level++) {
    const next: [number, number][] = [];
    for (let i = 0; i < pts.length - 1; i++) {
      const [x1, y1] = pts[i];
      const [x2, y2] = pts[i + 1];
      next.push(pts[i]);
      const r = rand(seed * 131 + level * 977 + i * 13) - 0.5;
      next.push([(x1 + x2) / 2 + r * amp * 0.25, (y1 + y2) / 2 + r * amp]);
    }
    next.push(pts[pts.length - 1]);
    pts = next;
    amp *= 0.55;
  }
  const d = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const [lx] = pts[pts.length - 1];
  return close === "left" ? `${d} L${lx} ${H} L0 ${H}Z` : `${d} L${lx} ${H} L${W} ${H}Z`;
}

const LEFT_FAR = ridge([[0, 470], [140, 360], [250, 175], [330, 290], [470, 420], [600, 515], [700, 560]], 70, 1, "left");
const RIGHT_FAR = ridge([[1440, 500], [1300, 390], [1150, 235], [1060, 320], [930, 440], [820, 520], [745, 560]], 70, 2, "right");
const LEFT_NEAR = ridge([[0, 540], [130, 430], [260, 380], [380, 400], [500, 470], [620, 535], [700, 566]], 44, 3, "left");
const RIGHT_NEAR = ridge([[1440, 560], [1320, 450], [1190, 395], [1060, 420], [940, 480], [830, 540], [742, 568]], 44, 4, "right");

/** Blue-lit rock specks on the inner cliff faces near the falls (the reference's sparkling rock texture). */
function CliffTexture({ animate }: { animate: boolean }) {
  const specks = Array.from({ length: 420 }, (_, i) => {
    const side = rand(i + 101) < 0.5 ? -1 : 1;
    const t = rand(i + 103); // 0 near the falls .. 1 far
    const dx = side * (70 + t * 360);
    const y = LIP - 6 + rand(i + 107) * (H - LIP) * (0.35 + t * 0.65) - (1 - t) * 30;
    const near = 1 - t;
    return {
      x: CX + dx + (rand(i + 109) - 0.5) * 30,
      y,
      w: 1 + rand(i + 113) * 3,
      o: 0.08 + near * near * 0.75 * rand(i + 117),
      tw: rand(i + 119) < 0.12,
    };
  });
  return (
    <g>
      {specks.map((p, i) => (
        <rect
          key={i}
          x={p.x}
          y={p.y}
          width={p.w}
          height={p.w * 0.7}
          fill={p.o > 0.4 ? "#9ccbff" : "#2f6fd6"}
          opacity={p.o}
          className={animate && p.tw ? "sx-twinkle" : undefined}
          style={p.tw ? { animationDuration: `${2 + (i % 4)}s`, animationDelay: `${-(i % 7) * 0.4}s` } : undefined}
        />
      ))}
    </g>
  );
}

function Waterfall({ id, animate }: { id: string; animate: boolean }) {
  const streaks = Array.from({ length: 110 }, (_, i) => {
    const spread = (rand(i + 1) - 0.5) * 2; // -1..1
    const x = CX + spread * 128 * (0.3 + rand(i + 7) * 0.7);
    const w = 0.6 + rand(i + 3) * 1.8;
    const o = 0.12 + (1 - Math.abs(spread)) * 0.55 * rand(i + 11);
    const dash = 18 + rand(i + 5) * 60;
    const gap = 10 + rand(i + 9) * 50;
    const dur = 1.6 + rand(i + 13) * 2.4;
    return { x, w, o, dash, gap, dur, delay: -rand(i + 17) * dur };
  });
  return (
    <g>
      {/* the falling sheet: wide soft glow, then streaks, then the bright core */}
      <rect x={CX - 150} y={LIP} width={300} height={H - LIP} fill={`url(#${id}-sheet)`} />
      {streaks.map((s, i) => (
        <line
          key={i}
          x1={s.x}
          x2={s.x + (rand(i + 21) - 0.5) * 6}
          y1={LIP + 4}
          y2={H}
          stroke="#8FC0FF"
          strokeOpacity={s.o}
          strokeWidth={s.w}
          strokeDasharray={`${s.dash} ${s.gap}`}
          className={animate ? "sx-fall" : undefined}
          style={{ animationDuration: `${s.dur}s`, animationDelay: `${s.delay}s` }}
        />
      ))}
      <rect x={CX - 22} y={LIP - 6} width={44} height={H - LIP + 6} fill="#4699F5" opacity={0.55} filter={`url(#${id}-blur12)`} />
      <rect x={CX - 2.2} y={LIP - 4} width={4.4} height={H - LIP + 4} fill={`url(#${id}-core)`} />
    </g>
  );
}

function Sparks({ animate }: { animate: boolean }) {
  const dots = Array.from({ length: 90 }, (_, i) => {
    const side = rand(i + 31) < 0.5 ? -1 : 1;
    const dx = side * (20 + rand(i + 33) * 260);
    const x = CX + dx;
    const y = LIP - 4 - rand(i + 37) * 26 + Math.abs(dx) * 0.06 * rand(i + 39);
    return { x, y, r: 0.6 + rand(i + 41) * 1.5, o: 0.25 + rand(i + 43) * 0.7, d: 1.5 + rand(i + 45) * 3 };
  });
  return (
    <g>
      {dots.map((d, i) => (
        <circle
          key={i}
          cx={d.x}
          cy={d.y}
          r={d.r}
          fill="#9CCBFF"
          opacity={d.o}
          className={animate ? "sx-twinkle" : undefined}
          style={{ animationDuration: `${d.d}s`, animationDelay: `${-d.d * rand(i + 47)}s` }}
        />
      ))}
    </g>
  );
}

/**
 * The hero mark: Spectra's prism as a faceted, lit gem (original artwork;
 * not a cube cluster). Floats gently unless reduced motion is set.
 */
export function HeroMark({ size = 96 }: { size?: number }) {
  const id = useId().replace(/:/g, "");
  const reduce = useReducedMotion() ?? false;
  return (
    <motion.svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      animate={reduce ? undefined : { y: [0, -6, 0] }}
      transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
      style={{ filter: "drop-shadow(0 0 18px rgba(70,153,245,.65)) drop-shadow(0 0 42px rgba(42,102,204,.4))" }}
    >
      <defs>
        <linearGradient id={`${id}-a`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#d6ebff" />
          <stop offset="1" stopColor="#5da2f7" />
        </linearGradient>
        <linearGradient id={`${id}-b`} x1="1" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#5da2f7" />
          <stop offset="1" stopColor="#1a57bb" />
        </linearGradient>
        <linearGradient id={`${id}-c`} x1="0" y1="1" x2="1" y2="0">
          <stop offset="0" stopColor="#15418a" />
          <stop offset="1" stopColor="#2a66cc" />
        </linearGradient>
      </defs>
      {/* outer facets */}
      <path d="M50 6 L50 50 L14 50Z" fill={`url(#${id}-a)`} />
      <path d="M50 6 L86 50 L50 50Z" fill={`url(#${id}-b)`} />
      <path d="M14 50 L50 50 L50 94Z" fill={`url(#${id}-c)`} />
      <path d="M86 50 L50 94 L50 50Z" fill="#0f3a86" />
      {/* inner prism + spectrum line */}
      <path d="M50 26 L66 50 L50 74 L34 50Z" fill="none" stroke="#e8f3ff" strokeOpacity="0.85" strokeWidth="1.4" />
      <path d="M50 6 L86 50 L50 94 L14 50Z" fill="none" stroke="#bfe0ff" strokeOpacity="0.6" strokeWidth="1" />
      <circle cx="50" cy="50" r="2.4" fill="#fff" />
    </motion.svg>
  );
}

export default function HeroScene({ focal }: { focal?: ReactNode }) {
  const id = useId().replace(/:/g, "");
  const reduce = useReducedMotion() ?? false;
  const px = useMotionValue(0);
  const py = useMotionValue(0);
  const sx = useSpring(px, { stiffness: 40, damping: 18 });
  const sy = useSpring(py, { stiffness: 40, damping: 18 });

  useEffect(() => {
    if (reduce) return;
    const onMove = (e: PointerEvent) => {
      px.set((e.clientX / window.innerWidth - 0.5) * 2); // -1..1
      py.set((e.clientY / window.innerHeight - 0.5) * 2);
    };
    window.addEventListener("pointermove", onMove);
    return () => window.removeEventListener("pointermove", onMove);
  }, [reduce, px, py]);

  const far = useParallax(-6, sx, sy);
  const near = useParallax(-14, sx, sy);
  const mist = useParallax(10, sx, sy);
  const mark = useParallax(-3, sx, sy);

  return (
    <div className="sx-scene" aria-hidden>
      <svg className="sx-scene-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id={`${id}-sky`} cx="0.5" cy="0.28" r="0.75">
            <stop offset="0" stopColor="#2e3036" />
            <stop offset="0.5" stopColor="#15161a" />
            <stop offset="1" stopColor="#000" />
          </radialGradient>
          <linearGradient id={`${id}-rockFar`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#16171b" />
            <stop offset="0.5" stopColor="#0e0f12" />
            <stop offset="1" stopColor="#050506" />
          </linearGradient>
          <linearGradient id={`${id}-rockNear`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#0d1016" />
            <stop offset="1" stopColor="#020203" />
          </linearGradient>
          {/* blue rim light on the rocks nearest the falls */}
          <radialGradient id={`${id}-rim`} cx={CX} cy={LIP} r={460} gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#2f7dff" stopOpacity="0.9" />
            <stop offset="0.35" stopColor="#1a57bb" stopOpacity="0.35" />
            <stop offset="1" stopColor="#1a57bb" stopOpacity="0" />
          </radialGradient>
          <linearGradient id={`${id}-sheet`} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#1a57bb" stopOpacity="0" />
            <stop offset="0.35" stopColor="#1f63d6" stopOpacity="0.22" />
            <stop offset="0.5" stopColor="#4699f5" stopOpacity="0.38" />
            <stop offset="0.65" stopColor="#1f63d6" stopOpacity="0.22" />
            <stop offset="1" stopColor="#1a57bb" stopOpacity="0" />
          </linearGradient>
          <linearGradient id={`${id}-core`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#e8f3ff" />
            <stop offset="0.4" stopColor="#9fd0ff" />
            <stop offset="1" stopColor="#4699f5" stopOpacity="0.7" />
          </linearGradient>
          <radialGradient id={`${id}-pool`} cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#4699f5" stopOpacity="0.55" />
            <stop offset="1" stopColor="#4699f5" stopOpacity="0" />
          </radialGradient>
          <radialGradient id={`${id}-mistG`} cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#5a5e66" stopOpacity="0.35" />
            <stop offset="1" stopColor="#5a5e66" stopOpacity="0" />
          </radialGradient>
          <radialGradient id={`${id}-vignette`} cx="0.5" cy="0.45" r="0.75">
            <stop offset="0.55" stopColor="#000" stopOpacity="0" />
            <stop offset="1" stopColor="#000" stopOpacity="0.95" />
          </radialGradient>
          <filter id={`${id}-blur12`} x="-50%" y="-10%" width="200%" height="120%">
            <feGaussianBlur stdDeviation="12" />
          </filter>
          <filter id={`${id}-blur30`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="30" />
          </filter>
          <filter id={`${id}-grain`}>
            <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="7" />
            <feColorMatrix values="0 0 0 0 0.5  0 0 0 0 0.55  0 0 0 0 0.62  0 0 0 0.10 0" />
            <feComposite in2="SourceGraphic" operator="in" />
          </filter>
        </defs>

        <rect width={W} height={H} fill={`url(#${id}-sky)`} />

        {/* drifting mist behind the peaks */}
        <motion.g style={mist}>
          <ellipse cx={360} cy={260} rx={380} ry={120} fill={`url(#${id}-mistG)`} className={reduce ? undefined : "sx-mist"} />
          <ellipse cx={1120} cy={230} rx={360} ry={110} fill={`url(#${id}-mistG)`} className={reduce ? undefined : "sx-mist sx-mist-b"} />
          <ellipse cx={720} cy={380} rx={520} ry={120} fill={`url(#${id}-mistG)`} opacity={0.7} />
        </motion.g>

        {/* far range */}
        <motion.g style={far}>
          <path d={LEFT_FAR} fill={`url(#${id}-rockFar)`} />
          <path d={RIGHT_FAR} fill={`url(#${id}-rockFar)`} />
          {/* faint ridge highlights */}
          <path d="M232 205 L268 214 L300 262 L338 300" stroke="#3a3d44" strokeWidth="1.2" fill="none" opacity="0.6" />
          <path d="M1140 250 L1112 268 L1080 300 L1040 340" stroke="#3a3d44" strokeWidth="1.2" fill="none" opacity="0.5" />
          <path d={LEFT_FAR} fill="#000" filter={`url(#${id}-grain)`} opacity="0.9" />
          <path d={RIGHT_FAR} fill="#000" filter={`url(#${id}-grain)`} opacity="0.9" />
        </motion.g>

        {/* near cliffs lit blue at the lip */}
        <motion.g style={near}>
          <path d={LEFT_NEAR} fill={`url(#${id}-rockNear)`} />
          <path d={RIGHT_NEAR} fill={`url(#${id}-rockNear)`} />
          <path d={LEFT_NEAR} fill={`url(#${id}-rim)`} opacity="0.85" />
          <path d={RIGHT_NEAR} fill={`url(#${id}-rim)`} opacity="0.85" />
          <path d={LEFT_NEAR} fill="#000" filter={`url(#${id}-grain)`} />
          <path d={RIGHT_NEAR} fill="#000" filter={`url(#${id}-grain)`} />
          {/* glowing lip */}
          <ellipse cx={CX} cy={LIP + 6} rx={230} ry={18} fill="#2f7dff" opacity="0.45" filter={`url(#${id}-blur12)`} />
          <path d="M520 548 Q620 566 720 562 Q820 566 930 546" stroke="#6fb0ff" strokeWidth="1.5" fill="none" opacity="0.7" />
          <CliffTexture animate={!reduce} />
          <Sparks animate={!reduce} />
          <Waterfall id={id} animate={!reduce} />
          <ellipse cx={CX} cy={H - 10} rx={300} ry={70} fill={`url(#${id}-pool)`} filter={`url(#${id}-blur30)`} />
        </motion.g>

        <rect width={W} height={H} fill={`url(#${id}-vignette)`} />
      </svg>

      <motion.div className="sx-scene-focal" style={mark}>
        {focal}
      </motion.div>
    </div>
  );
}
