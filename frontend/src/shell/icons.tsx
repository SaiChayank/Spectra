/* Small outlined nav icons (24 px grid, 1.5 px stroke, currentColor). Decorative: aria-hidden. */
import type { ReactNode } from "react";

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {children}
    </svg>
  );
}

export const NAV_ICONS: Record<string, ReactNode> = {
  overview: (
    <Icon>
      <rect x="3" y="3" width="7" height="9" />
      <rect x="14" y="3" width="7" height="5" />
      <rect x="14" y="12" width="7" height="9" />
      <rect x="3" y="16" width="7" height="5" />
    </Icon>
  ),
  monitor: (
    <Icon>
      <path d="M3 12h4l3-7 4 14 3-7h4" />
    </Icon>
  ),
  incidents: (
    <Icon>
      <path d="M12 3 2 20h20Z" />
      <path d="M12 10v4M12 17v.5" />
    </Icon>
  ),
  hosts: (
    <Icon>
      <rect x="3" y="4" width="18" height="12" />
      <path d="M8 20h8M12 16v4" />
    </Icon>
  ),
  traffic: (
    <Icon>
      <path d="M4 7h13l-3-3M20 17H7l3 3" />
    </Icon>
  ),
  network: (
    <Icon>
      <rect x="10" y="3" width="4" height="4" />
      <rect x="3" y="17" width="4" height="4" />
      <rect x="17" y="17" width="4" height="4" />
      <path d="M12 7v5M5 17v-3h14v3" />
    </Icon>
  ),
  models: (
    <Icon>
      <path d="M12 3 21 8v8l-9 5-9-5V8Z" />
      <path d="M3 8l9 5 9-5M12 13v8" />
    </Icon>
  ),
  audit: (
    <Icon>
      <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6Z" />
      <path d="m9 12 2 2 4-4" />
    </Icon>
  ),
  system: (
    <Icon>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1 7 17M17 7l2.1-2.1" />
    </Icon>
  ),
  account: (
    <Icon>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c1-4 4.5-6 8-6s7 2 8 6" />
    </Icon>
  ),
  experimental: (
    <Icon>
      <path d="M9 3h6M10 3v6l-5 10a1 1 0 0 0 1 2h12a1 1 0 0 0 1-2l-5-10V3" />
    </Icon>
  ),
  search: (
    <Icon>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-4-4" />
    </Icon>
  ),
  menu: (
    <Icon>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </Icon>
  ),
  collapse: (
    <Icon>
      <path d="m15 6-6 6 6 6" />
    </Icon>
  ),
  expand: (
    <Icon>
      <path d="m9 6 6 6-6 6" />
    </Icon>
  ),
};
