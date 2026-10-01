import { useCallback, useEffect, useState } from "react";

/**
 * The nine console sections, in nav order. Hash routes — no router library:
 * `#/overview`, `#/incidents/12` (deep link to one investigation), ...
 */
export const SECTIONS = [
  "overview",
  "monitor",
  "incidents",
  "traffic",
  "network",
  "models",
  "audit",
  "modules",
  "system",
] as const;

export type Section = (typeof SECTIONS)[number];

export const SECTION_LABELS: Record<Section, string> = {
  overview: "Overview",
  monitor: "Monitor",
  incidents: "Incidents",
  traffic: "Traffic",
  network: "Network",
  models: "Models",
  audit: "Audit",
  modules: "Modules",
  system: "System",
};

export type Route =
  | { kind: "landing" }
  | { kind: "login" }
  | { kind: "console"; section: Section; incidentId: number | null };

function isSection(value: string): value is Section {
  return (SECTIONS as readonly string[]).includes(value);
}

/** Current `location.hash` → route (unknown hashes fall back to landing). */
export function parseHash(): Route {
  const raw = window.location.hash.replace(/^#\/?/, "");
  if (raw === "") return { kind: "landing" };
  if (raw === "login") return { kind: "login" };
  const [head, second] = raw.split("/");
  if (head === "incidents") {
    const id =
      second !== undefined && /^\d+$/.test(second) ? Number(second) : null;
    return { kind: "console", section: "incidents", incidentId: id };
  }
  if (isSection(head)) return { kind: "console", section: head, incidentId: null };
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
  const [route, setRoute] = useState<Route>(parseHash);

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
