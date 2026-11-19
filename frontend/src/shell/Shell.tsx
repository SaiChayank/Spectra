import { useState, type FormEvent, type ReactNode } from "react";
import { DotGridBackground, Drawer, RoleChip, SkewButton, SpectraMark, StatusPill, Wordmark, type Status } from "../components/ui";
import type { CaptureStatus, Identity, ModelInfo } from "../lib/api";
import {
  EXPERIMENTAL,
  EXPERIMENTAL_LABELS,
  SECTION_LABELS,
  type ExperimentalModule,
  type Section,
} from "../lib/router";
import { NAV_ICONS } from "./icons";
import SearchDrawer from "./SearchDrawer";
import "./shell.css";
import "./legacy.css";

/** Sidebar order (Account and Experimental are rendered separately). */
const MAIN: Section[] = ["overview", "monitor", "captures", "incidents", "hosts", "traffic", "network", "models", "audit", "system"];

/** Sections the server gates behind `investigate` (shown, but restricted). */
const INVESTIGATE_ONLY: Section[] = ["incidents", "network", "audit"];

/** Not built yet: needs a proposed backend endpoint (frontend-plan §6). */
const PLANNED: Section[] = ["hosts"];

export type LiveState = "live" | "reconnecting" | "offline";

const COLLAPSE_KEY = "spectra-ui-sidebar-collapsed"; // UI preference only

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

export interface ShellProps {
  identity: Identity;
  section: Section;
  module: ExperimentalModule | null;
  title: string;
  can: (permission: string) => boolean;
  capture: CaptureStatus | undefined;
  model: ModelInfo | undefined;
  live: LiveState;
  onSignOut: () => void;
  /** Global banners (storage, offline, untrained model, capture error), shown under the top bar. */
  banners?: ReactNode;
  children: ReactNode;
}

function NavList({
  section,
  module,
  can,
  collapsed,
  onPick,
}: {
  section: Section;
  module: ExperimentalModule | null;
  can: (p: string) => boolean;
  collapsed: boolean;
  onPick?: () => void;
}) {
  const item = (id: Section, href: string, label: string, note?: string, current = section === id) => (
    <li key={href}>
      <a
        href={href}
        className="sx-nav-item"
        aria-current={current ? "page" : undefined}
        title={collapsed ? `${label}${note ? ` (${note})` : ""}` : undefined}
        onClick={onPick}
      >
        <span className="sx-nav-icon">{NAV_ICONS[id]}</span>
        <span className="sx-nav-label">{label}</span>
        {note && !collapsed ? <span className="sx-nav-note">{note}</span> : null}
        {note && collapsed ? <span className="sx-visually-hidden"> ({note})</span> : null}
      </a>
    </li>
  );
  return (
    <nav aria-label="Console sections" className="sx-nav">
      <ul>
        {MAIN.map((id) =>
          item(
            id,
            `#/${id}`,
            SECTION_LABELS[id],
            PLANNED.includes(id) ? "planned" : !can("investigate") && INVESTIGATE_ONLY.includes(id) ? "restricted" : undefined,
          ),
        )}
      </ul>
      <p className="sx-nav-group sx-eyebrow" aria-hidden={collapsed || undefined}>
        {collapsed ? "" : "Experimental"}
      </p>
      <ul aria-label="Experimental modules (simulated or frozen)">
        {EXPERIMENTAL.map((m) =>
          item("experimental", `#/experimental/${m}`, EXPERIMENTAL_LABELS[m], "simulated", section === "experimental" && module === m),
        )}
      </ul>
      <ul className="sx-nav-bottom">{item("account", "#/account", SECTION_LABELS.account)}</ul>
    </nav>
  );
}

function captureState(capture: CaptureStatus | undefined): { status: Status; label: string } {
  if (!capture) return { status: "idle", label: "Capture: unknown" };
  if (capture.error) return { status: "error", label: "Capture error" };
  if (capture.running) return { status: "ok", label: "Capturing" };
  return { status: "idle", label: "Capture idle" };
}

export default function Shell({
  identity,
  section,
  module,
  title,
  can,
  capture,
  model,
  live,
  onSignOut,
  banners,
  children,
}: ShellProps) {
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [menuOpen, setMenuOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [searched, setSearched] = useState<string | null>(null);

  const toggleCollapsed = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      } catch {
        /* preference not saved: fine */
      }
      return !c;
    });
  };

  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (q.length >= 2) setSearched(q);
  };

  const cap = captureState(capture);
  const liveLabel = { live: "Live events", reconnecting: "Reconnecting", offline: "Events offline" }[live];

  return (
    <div className="sx sx-shell" data-collapsed={collapsed}>
      <a className="sx-skip" href="#sx-main">
        Skip to content
      </a>
      <aside className="sx-sidebar" aria-label="Sidebar">
        <div className="sx-sidebar-head">
          <a href="#/overview" className="sx-brand" aria-label="Spectra overview">
            {collapsed ? <SpectraMark size={26} /> : <Wordmark size={14} />}
          </a>
        </div>
        <NavList section={section} module={module} can={can} collapsed={collapsed} />
        <button
          type="button"
          className="sx-collapse"
          onClick={toggleCollapsed}
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? NAV_ICONS.expand : NAV_ICONS.collapse}
        </button>
      </aside>

      <div className="sx-main-col">
        <header className="sx-topbar">
          <button type="button" className="sx-menu-btn" aria-label="Open navigation" onClick={() => setMenuOpen(true)}>
            {NAV_ICONS.menu}
          </button>
          <h1 className="sx-topbar-title">{title}</h1>
          <form className="sx-search" role="search" onSubmit={submitSearch}>
            <label htmlFor="sx-global-search" className="sx-visually-hidden">
              Search alerts, incidents, flows and hosts
            </label>
            <span className="sx-search-icon">{NAV_ICONS.search}</span>
            <input
              id="sx-global-search"
              className="sx-input"
              type="search"
              placeholder="Search IP, SNI, JA3/JA4, alert id…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
            />
          </form>
          <div className="sx-topbar-status">
            <StatusPill status={cap.status}>{cap.label}</StatusPill>
            <StatusPill status={live}>{liveLabel}</StatusPill>
            <StatusPill status={model === undefined ? "idle" : model.trained ? "ok" : "warn"}>
              {model === undefined ? "Model: unknown" : model.trained ? "Model ready" : "No model"}
            </StatusPill>
          </div>
          <div className="sx-topbar-user">
            <a href="#/account" className="sx-user" title={`Permissions: ${identity.user.permissions.join(", ")}`}>
              <span className="sx-user-name">{identity.user.username}</span>
              <RoleChip role={identity.user.role} />
            </a>
            <SkewButton variant="ghost" size="sm" onClick={onSignOut}>
              Sign out
            </SkewButton>
          </div>
        </header>

        {banners ? <div className="sx-banners">{banners}</div> : null}

        <main id="sx-main" className="sx-content" tabIndex={-1}>
          <DotGridBackground opacity={0.03} fade="40%" />
          <div className="sx-content-inner">{children}</div>
        </main>
      </div>

      <Drawer open={menuOpen} onClose={() => setMenuOpen(false)} title="Spectra">
        <NavList section={section} module={module} can={can} collapsed={false} onPick={() => setMenuOpen(false)} />
      </Drawer>
      <SearchDrawer query={searched} onClose={() => setSearched(null)} />
    </div>
  );
}
