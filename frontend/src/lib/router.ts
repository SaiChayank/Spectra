import { useCallback, useEffect, useState } from "react";

/**
 * Console sections, in sidebar order. Hash routes, no router library:
 * `#/overview`, `#/incidents/12` (deep link to one investigation),
 * `#/experimental/tee` (one experimental module), ...
 */
export const SECTIONS = [
  "overview",
  "monitor",
  "captures",
  "incidents",
  "hosts",
  "traffic",
  "network",
  "models",
  "audit",
  "system",
  "account",
  "experimental",
] as const;

export type Section = (typeof SECTIONS)[number];

export const SECTION_LABELS: Record<Section, string> = {
  overview: "Overview",
  monitor: "Monitor",
  captures: "Captures & model",
  incidents: "Alerts & Incidents",
  hosts: "Hosts",
  traffic: "Traffic",
  network: "Network",
  models: "Models",
  audit: "Audit",
  system: "System",
  account: "Account",
  experimental: "Experimental",
};

/** Frozen / simulated modules, grouped under "Experimental" (docs/35 §9). */
export const EXPERIMENTAL = ["pqc", "tee", "bio", "twin", "edge"] as const;
export type ExperimentalModule = (typeof EXPERIMENTAL)[number];

export const EXPERIMENTAL_LABELS: Record<ExperimentalModule, string> = {
  pqc: "PQC readiness",
  tee: "TEE",
  bio: "Bio-inspired",
  twin: "Digital twin",
  edge: "Edge / 5G",
};

export type Route =
  | { kind: "landing" }
  | { kind: "login" }
  | {
      kind: "console";
      section: Section;
      incidentId: number | null;
      module: ExperimentalModule | null;
    };

function isSection(value: string): value is Section {
  return (SECTIONS as readonly string[]).includes(value);
}

function isModule(value: string | undefined): value is ExperimentalModule {
  return value !== undefined && (EXPERIMENTAL as readonly string[]).includes(value);
}

/** A hash → route (unknown hashes fall back to landing). */
export function parseHash(hash: string = window.location.hash): Route {
  const raw = hash.replace(/^#\/?/, "");
  if (raw === "") return { kind: "landing" };
  if (raw === "login") return { kind: "login" };
  const [head, second] = raw.split("/");
  const base = { kind: "console" as const, incidentId: null, module: null };
  if (head === "incidents") {
    const id = second !== undefined && /^\d+$/.test(second) ? Number(second) : null;
    return { ...base, section: "incidents", incidentId: id };
  }
  // `#/modules` was the old single page for all experimental modules
  if (head === "experimental" || head === "modules") {
    return { ...base, section: "experimental", module: isModule(second) ? second : null };
  }
  if (isSection(head)) return { ...base, section: head };
  return { kind: "landing" };
}

/** Navigate by hash (`navigate("#/incidents/12")`). */
export function navigate(path: string): void {
  window.location.hash = path.startsWith("#") ? path : `#${path}`;
}

/**
 * Reactive hash route. `navigate` is safe to call from anywhere; components
 * re-render on `hashchange` (back/forward buttons included).
 */
export function useRoute(): [Route, (path: string) => void] {
  const [route, setRoute] = useState<Route>(() => parseHash());

  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const go = useCallback((path: string) => navigate(path), []);
  return [route, go];
}

/** Build a section path (`sectionPath("models")` → `"#/models"`). */
export const sectionPath = (section: Section): string => `#/${section}`;
