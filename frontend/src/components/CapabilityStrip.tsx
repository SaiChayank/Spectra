import { useEffect, useState } from "react";
import { api, type CapabilityModule, type CapabilityReport } from "../lib/api";

/**
 * Maturity colour-coding: REAL/LOCAL read as real functionality, SIMULATED
 * and EXPERIMENTAL always stand apart so the two never look alike.
 */
function maturityClass(status: string): string {
  switch (status) {
    case "REAL":
      return "cap-real";
    case "LOCAL":
      return "cap-local";
    case "SIMULATED":
      return "cap-simulated";
    case "EXPERIMENTAL":
      return "cap-experimental";
    case "HARDWARE_BACKED":
      return "cap-hardware";
    default:
      return "cap-unavailable";
  }
}

/** One module's chip: title + maturity up front, contract details in the
 * tooltip (input, output, scoring effect, failure behaviour, live status). */
export function CapabilityBadge({ mod }: { mod: CapabilityModule }) {
  const availability = mod.available === false ? "down" : mod.available ? "up" : "unknown";
  const title = [
    `${mod.status} — ${mod.note}`,
    `Consumes: ${mod.consumes}`,
    `Produces: ${mod.produces}`,
    `Alert scoring: ${mod.affects_alert_scoring ? "may adjust confidence/severity" : "never — evidence only"}`,
    `Failure behaviour: ${mod.failure}`,
    `Live status: ${mod.detail ?? "not probed"}`,
    mod.failures ? `Recorded degradations: ${mod.failures}` : undefined,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <span className={`cap-badge ${maturityClass(mod.status)}`} title={title}>
      <span className={`cap-dot ${availability}`} aria-hidden />
      <span className="cap-title">{mod.title}</span>
      <span className="cap-status">{mod.status}</span>
    </span>
  );
}

/**
 * Capability status driven by GET /api/capabilities.
 *
 * `keys` limits the strip to specific modules (a panel shows its own);
 * `showPolicy` appends the scoring policy line (the overview shows all).
 * Supplementary display: renders nothing while loading or on failure.
 */
export default function CapabilityStrip({
  keys,
  showPolicy = false,
}: {
  keys?: string[];
  showPolicy?: boolean;
}) {
  const [report, setReport] = useState<CapabilityReport | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .capabilities()
      .then((next) => {
        if (alive) setReport(next);
      })
      .catch(() => {
        // Supplementary status: panels keep their own content, but the
        // overview (showPolicy) says so instead of showing an empty card.
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  if (failed) return showPolicy ? <p className="note">Capability status unavailable.</p> : null;
  if (!report) return null;
  const entries = (keys ?? Object.keys(report.modules))
    .map((key) => report.modules[key])
    .filter((mod): mod is CapabilityModule => Boolean(mod));

  return (
    <div className="cap-strip">
      {entries.map((mod) => (
        <CapabilityBadge key={mod.title} mod={mod} />
      ))}
      {showPolicy && (
        <p className="note" style={{ flexBasis: "100%", marginBottom: 0 }}>
          {report.scoring_policy}
        </p>
      )}
    </div>
  );
}
