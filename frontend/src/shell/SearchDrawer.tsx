import { useEffect, useState } from "react";
import { Badge, CodeValue, Drawer, EmptyState, ErrorState, Eyebrow, Loading, PermissionDenied, SeverityBadge } from "../components/ui";
import { ApiError, api, type SearchResults } from "../lib/api";

/** Readable label for a search section key (`alerts` → "Alerts"). */
const label = (key: string) => key.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());

/** Where a result row links to, when the console has a page for it. */
function linkFor(section: string, item: Record<string, unknown>): string | null {
  if (section === "incidents" && typeof item.id === "number") return `#/incidents/${item.id}`;
  if (section === "alerts") return "#/incidents";
  if (section === "flows" || section === "detections") return "#/traffic";
  return null;
}

/** The few fields that identify a row, in a stable order; everything is metadata. */
const SHOWN = ["alert_id", "id", "title", "threat_type", "severity", "status", "src", "dst", "destination", "sni", "ja3", "ja4", "host"];
const CODE = new Set(["alert_id", "src", "dst", "destination", "ja3", "ja4", "host"]);

function Row({ section, item }: { section: string; item: Record<string, unknown> }) {
  const keys = SHOWN.filter((k) => item[k] !== undefined && item[k] !== null && item[k] !== "").slice(0, 4);
  const href = linkFor(section, item);
  const body = (
    <dl className="sx-kv" style={{ gridTemplateColumns: "90px 1fr" }}>
      {keys.map((k) => (
        <div key={k} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>
            {CODE.has(k) ? (
              <CodeValue value={String(item[k])} label={k} />
            ) : k === "severity" ? (
              <SeverityBadge level={String(item[k])} />
            ) : k === "threat_type" && item[k] === "C2_BEACONING" ? (
              <span style={{ display: "inline-flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                C2_BEACONING <Badge tone="blue">Ranking aid, not a proven detector</Badge>
              </span>
            ) : (
              String(item[k])
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
  return (
    <li className="sx-search-row">
      {body}
      {href ? (
        <a href={href} className="sx-hint">
          Open in {section === "incidents" ? "incident" : section === "alerts" ? "Alerts & Incidents" : "Traffic"} →
        </a>
      ) : null}
    </li>
  );
}

/** Global search results (GET /api/search), opened from the top bar. */
export default function SearchDrawer({ query, onClose }: { query: string | null; onClose: () => void }) {
  const [state, setState] = useState<{ q: string; data?: SearchResults; error?: unknown } | null>(null);

  useEffect(() => {
    if (!query) return;
    let live = true;
    api
      .search(query, 10)
      .then((data) => live && setState({ q: query, data }))
      .catch((error: unknown) => live && setState({ q: query, error }));
    return () => {
      live = false;
    };
  }, [query]);

  const current = state && state.q === query ? state : null;
  const sections = Object.entries(current?.data?.results ?? {}).filter(([, s]) => s.count > 0);

  return (
    <Drawer open={query !== null} onClose={onClose} title={`Search: ${query ?? ""}`}>
      {!current ? (
        <Loading label="Searching" />
      ) : current.error ? (
        current.error instanceof ApiError && current.error.status === 403 ? (
          <PermissionDenied permission="read" what="search" />
        ) : (
          <ErrorState title="Search failed" detail={current.error instanceof Error ? current.error.message : String(current.error)} />
        )
      ) : sections.length === 0 ? (
        <EmptyState title="No matches">Search looks at addresses, server names (SNI), JA3/JA4 fingerprints and alert or incident ids.</EmptyState>
      ) : (
        <div style={{ display: "grid", gap: 20 }}>
          <p className="sx-hint">
            {current.data!.count} match{current.data!.count === 1 ? "" : "es"}, up to {current.data!.limit} per kind. Matched as:{" "}
            {current.data!.kinds.join(", ")}.
          </p>
          {sections.map(([key, s]) => (
            <section key={key} style={{ display: "grid", gap: 8 }}>
              <Eyebrow as="h3">
                {label(key)} · {s.count}
              </Eyebrow>
              <ul className="sx-search-list">
                {s.items.map((item, i) => (
                  <Row key={i} section={key} item={item} />
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </Drawer>
  );
}
