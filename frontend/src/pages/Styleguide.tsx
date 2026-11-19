/**
 * Dev-only component gallery at `#/styleguide` (loaded from main.tsx only when
 * import.meta.env.DEV). Every component in its states, on the real tokens.
 * Sample values are illustrative and labelled so; nothing here is product data.
 */
import { useState, type ReactNode } from "react";
import {
  Badge,
  Banner,
  Card,
  Checkbox,
  CodeValue,
  ConfirmDialog,
  CrosshairCard,
  DataTable,
  DotGridBackground,
  Drawer,
  EmptyState,
  ErrorState,
  Eyebrow,
  EvidenceList,
  FileDrop,
  GraphSample,
  HeroFocal,
  Input,
  KeyValue,
  LightBeam,
  Loading,
  Modal,
  PasswordInput,
  PermissionDenied,
  RoleChip,
  ScoreMeter,
  Select,
  SeverityBadge,
  SignalField,
  SkewButton,
  SkewTabs,
  StatCard,
  StatusPill,
  StorageBanner,
  Terrain,
  Textarea,
  TimeValue,
  Timeline,
  Toasts,
  Toggle,
  UntrainedBanner,
  Viewfinder,
  Wordmark,
  type ToastItem,
} from "../components/ui";
import { contrast } from "../lib/contrast";

const COLOURS: [string, string][] = [
  ["--bg-0", "#000000"],
  ["--bg-1", "#0A0B0D"],
  ["--surface-1", "#111214"],
  ["--surface-2", "#17181D"],
  ["--surface-3", "#202227"],
  ["--text-1", "#F5F5F5"],
  ["--text-2", "#A3A3A6"],
  ["--text-3", "#8E8E93"],
  ["--blue-500", "#1A57BB"],
  ["--blue-400", "#5DA2F7"],
  ["--blue-300", "#95C1F0"],
  ["--bracket", "#ABAEB4"],
  ["--gold-1", "#E3C89C"],
  ["--gold-2", "#D2A970"],
  ["--sev-critical", "#FF4D5E"],
  ["--sev-high", "#FF8A3D"],
  ["--sev-medium", "#F5C451"],
  ["--sev-low", "#4C8DFF"],
  ["--sev-info", "#8A94A6"],
  ["--ok", "#2FD08A"],
];

interface SampleRow {
  id: number;
  src: string;
  dst: string;
  sni: string | null;
  ja4: string;
  score: number;
  severity: string;
}

const SAMPLE_ROWS: SampleRow[] = Array.from({ length: 240 }, (_, i) => ({
  id: i + 1,
  src: `10.0.${i % 7}.${(i * 13) % 250}`,
  dst: `192.0.2.${(i * 7) % 250}:443`,
  sni: i % 5 === 0 ? null : `svc-${i % 9}.example.net`,
  ja4: `t13d1516h2_8daaf6152771_${(1000 + i * 37).toString(16).padStart(12, "0")}`,
  score: Math.round(((i * 37) % 1000) / 10),
  severity: ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"][i % 5],
}));

const COLUMNS = [
  { key: "id", header: "#", sort: (r: SampleRow) => r.id, align: "right" as const },
  { key: "src", header: "Source", code: (r: SampleRow) => r.src, sort: (r: SampleRow) => r.src },
  { key: "dst", header: "Destination", code: (r: SampleRow) => r.dst },
  { key: "sni", header: "SNI", render: (r: SampleRow) => r.sni ?? <span style={{ color: "var(--text-3)" }}>none</span>, sort: (r: SampleRow) => r.sni },
  { key: "ja4", header: "JA4", code: (r: SampleRow) => r.ja4 },
  { key: "score", header: "Score", sort: (r: SampleRow) => r.score, align: "right" as const, render: (r: SampleRow) => r.score.toFixed(0) },
  { key: "severity", header: "Severity", render: (r: SampleRow) => <SeverityBadge level={r.severity} />, sort: (r: SampleRow) => ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(r.severity) },
];

function Section({ title, note, children }: { title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section className="sx-sg-section" aria-labelledby={title}>
      <div style={{ display: "grid", gap: 4 }}>
        <Eyebrow as="h2">{title}</Eyebrow>
        {note ? <p className="sx-hint">{note}</p> : null}
      </div>
      {children}
    </section>
  );
}

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: "grid", gap: 6, justifyItems: "start" }}>
      <span className="sx-hint">{label}</span>
      {children}
    </div>
  );
}

export default function Styleguide() {
  const [tab, setTab] = useState<"alerts" | "incidents" | "hosts" | "frozen">("alerts");
  const [toggle, setToggle] = useState(true);
  const [progress, setProgress] = useState<number | undefined>(undefined);
  const [modal, setModal] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [tableState, setTableState] = useState<"data" | "loading" | "empty" | "error">("data");

  const fakeUpload = () => {
    setProgress(0);
    let p = 0;
    const t = setInterval(() => {
      p += 12;
      if (p >= 100) {
        clearInterval(t);
        setProgress(undefined);
        setToasts((ts) => [...ts, { id: Date.now(), tone: "ok", text: "Sample upload finished (styleguide demo, nothing was sent)." }]);
      } else setProgress(p);
    }, 250);
  };

  return (
    <div className="sx">
      <main className="sx-sg">
        <DotGridBackground opacity={0.03} />
        <header style={{ position: "relative", display: "grid", gap: 10, paddingBottom: 24 }}>
          <Wordmark />
          <h1 className="sx-page-title">
            Design system <span className="sx-gold">styleguide</span>
          </h1>
          <p style={{ maxWidth: "70ch" }}>
            Dev-only (<code>#/styleguide</code>, not in the production build). Colour values measured from the reference screenshots
            on 2026-11-19. Hover, focus and active are shown as forced states; the live ones work with mouse and keyboard.
          </p>
        </header>

        <Section title="Colour" note="Contrast ratio of each colour on surface-1 (AA: 4.5 for body text, 3.0 for large text and UI).">
          <div className="sx-sg-grid">
            {COLOURS.map(([name, hex]) => {
              const cr = contrast(hex, "#111214");
              return (
                <div key={name} className="sx-swatch">
                  <span className="sx-swatch-chip" style={{ background: hex }} />
                  <span className="sx-mono" style={{ color: "var(--text-1)" }}>
                    {name}
                  </span>
                  <span className="sx-mono">
                    {hex} · {cr.toFixed(2)}:1 {cr >= 4.5 ? "AA" : cr >= 3 ? "AA large/UI" : "fill only"}
                  </span>
                </div>
              );
            })}
          </div>
        </Section>

        <Section title="Typography">
          <p className="sx-display">
            See the flow.
            <br />
            Act on <span className="sx-gold">evidence</span>.
          </p>
          <h2 className="sx-section-title">Built to turn metadata into evidence</h2>
          <h2 className="sx-page-title">Alerts and incidents</h2>
          <Eyebrow>Metadata-only detection</Eyebrow>
          <p style={{ maxWidth: "60ch" }}>
            Body copy in text-2 at 14 px. Spectra reads flow statistics and TLS/QUIC handshake fields; payload bytes are never decrypted.
          </p>
          <p className="sx-hint">Caption in text-3 at 11 px.</p>
          <p className="sx-mono" style={{ color: "var(--text-1)" }}>
            10.0.4.17 → 192.0.2.10:443 · t13d1516h2_8daaf6152771 · 0123456789
          </p>
        </Section>

        <Section title="SkewButton">
          {(["primary", "secondary", "ghost", "danger"] as const).map((v) => (
            <div key={v} className="sx-sg-row">
              <Labeled label={`${v} · default`}>
                <SkewButton variant={v} icon={v === "primary" ? "⚡" : undefined} trailing={v === "secondary" ? "↗" : undefined}>
                  {v === "primary" ? "Sign in" : v === "secondary" ? "How it works" : v === "danger" ? "Delete" : "Cancel"}
                </SkewButton>
              </Labeled>
              <Labeled label="hover">
                <SkewButton variant={v} className="is-hover">
                  Action
                </SkewButton>
              </Labeled>
              <Labeled label="focus">
                <SkewButton variant={v} className="is-focus">
                  Action
                </SkewButton>
              </Labeled>
              <Labeled label="active">
                <SkewButton variant={v} className="is-active">
                  Action
                </SkewButton>
              </Labeled>
              <Labeled label="disabled">
                <SkewButton variant={v} disabled>
                  Action
                </SkewButton>
              </Labeled>
              <Labeled label="loading">
                <SkewButton variant={v} loading>
                  Saving
                </SkewButton>
              </Labeled>
            </div>
          ))}
          <div className="sx-sg-row">
            <Labeled label="sm">
              <SkewButton size="sm">Small</SkewButton>
            </Labeled>
            <Labeled label="md">
              <SkewButton>Medium</SkewButton>
            </Labeled>
            <Labeled label="lg">
              <SkewButton size="lg" icon="⚡">
                Large
              </SkewButton>
            </Labeled>
          </div>
        </Section>

        <Section title="SkewTabs" note="Arrow keys move between tabs; Home and End jump.">
          <SkewTabs
            label="Sample tabs"
            value={tab}
            onChange={setTab}
            items={[
              { id: "alerts", label: "Alerts" },
              { id: "incidents", label: "Incidents" },
              { id: "hosts", label: "Hosts" },
              { id: "frozen", label: "Disabled", disabled: true },
            ]}
          />
          <div className="sx-sg-row">
            <Labeled label="hover">
              <button type="button" className="sx-tab is-hover">
                Traffic
              </button>
            </Labeled>
            <Labeled label="focus">
              <button type="button" className="sx-tab is-focus">
                Traffic
              </button>
            </Labeled>
          </div>
        </Section>

        <Section title="Form controls">
          <div className="sx-sg-grid">
            <Input label="Username" placeholder="admin" autoComplete="off" />
            <Input label="Hover (forced)" className="sx-input is-hover" defaultValue="analyst" />
            <Input label="Focus (forced)" className="sx-input is-focus" defaultValue="viewer" />
            <Input label="With error" defaultValue="ab" error="Must be at least 3 characters." />
            <Input label="Disabled" disabled defaultValue="read only" />
            <PasswordInput label="Password" hint="At least 12 characters." autoComplete="new-password" />
            <Select
              label="Interface"
              options={[
                { value: "eth0", label: "eth0 · 192.0.2.4" },
                { value: "wlan0", label: "wlan0 · 198.51.100.7" },
              ]}
            />
            <Textarea label="Investigation note" placeholder="What did you check?" />
          </div>
          <div className="sx-sg-row">
            <Checkbox label="Include resolved alerts" defaultChecked />
            <Checkbox label="Disabled" disabled />
            <Toggle label={`Beacon detector ${toggle ? "on" : "off"}`} checked={toggle} onChange={setToggle} />
            <Toggle label="Disabled toggle" checked={false} onChange={() => {}} disabled />
          </div>
          <div style={{ maxWidth: 520 }}>
            <FileDrop onFile={fakeUpload} progress={progress} />
          </div>
          <SkewButton variant="ghost" size="sm" onClick={fakeUpload}>
            Simulate upload progress
          </SkewButton>
        </Section>

        <Section title="Badges, pills, chips" note="Severity always shows text and a distinct shape, never colour alone.">
          <div className="sx-sg-row">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
              <SeverityBadge key={s} level={s} />
            ))}
          </div>
          <div className="sx-sg-row">
            <Badge tone="warn" title="No trained model scored these flows">
              Unscored
            </Badge>
            <Badge>Simulated</Badge>
            <Badge tone="blue">Ranking aid, not a proven detector</Badge>
            <Badge tone="ok">Chain verified</Badge>
            <Badge tone="error">Chain broken</Badge>
          </div>
          <div className="sx-sg-row">
            <StatusPill status="live">Live</StatusPill>
            <StatusPill status="reconnecting">Reconnecting</StatusPill>
            <StatusPill status="offline">Offline</StatusPill>
            <StatusPill status="ok">Model ready</StatusPill>
            <StatusPill status="warn">No model</StatusPill>
            <StatusPill status="error">Capture failed</StatusPill>
            <RoleChip role="ADMIN" />
            <RoleChip role="ANALYST" />
            <RoleChip role="VIEWER" />
          </div>
        </Section>

        <Section title="Cards">
          <div className="sx-sg-grid">
            <CrosshairCard index="01" icon="⇣" title="Capture">
              Upload a PCAP or capture live from an interface. Payload is stripped on upload.
            </CrosshairCard>
            <CrosshairCard index="02" icon="≋" title="Flow metadata">
              Flow statistics and TLS/QUIC handshake fields: SNI, ALPN, versions, JA3/JA4.
            </CrosshairCard>
            <StatCard label="Flows" value="13" caption="sample value" trend={[3, 5, 4, 8, 7, 11, 13]} index="02" />
            <StatCard label="Detections" value="1" caption="sample value · threshold 0.19" delta={{ text: "+1 since last capture", direction: "up" }} focal />
            <Card title="Plain card" eyebrow="Active model">
              <KeyValue
                rows={[
                  ["Trained on", "42 flows (sample)"],
                  ["Contamination", <span className="sx-mono">0.02</span>],
                  ["Status", <StatusPill status="ok">Ready</StatusPill>],
                ]}
              />
            </Card>
          </div>
        </Section>

        <Section title="Viewfinder, score, evidence">
          <div className="sx-sg-row" style={{ alignItems: "flex-start" }}>
            <Viewfinder>
              <div style={{ padding: "12px 18px", color: "var(--text-1)" }}>Selected item</div>
            </Viewfinder>
            <div style={{ width: 360 }}>
              <ScoreMeter score={97.4} threshold={90} />
            </div>
            <div style={{ width: 360 }}>
              <ScoreMeter score={41} threshold={90} />
            </div>
            <div style={{ width: 360 }}>
              <ScoreMeter score={null} threshold={90} />
            </div>
          </div>
          <div style={{ maxWidth: 640 }}>
            <EvidenceList
              supporting={[
                { label: "Periodic forward timing", value: "0.04", unit: "CV", weight: 0.5, detail: "Packets left at near-constant intervals (sample)." },
                { label: "Rare destination", value: "1", unit: "of 412 hosts", weight: 0.3, detail: "Only one internal host talked to this destination (sample)." },
              ]}
              contradicting={[{ label: "Known SNI", value: "svc-1.example.net", detail: "The server name is common on this network (sample)." }]}
            />
          </div>
        </Section>

        <Section title="Values and time" note="Times are local; hover or focus shows UTC.">
          <div className="sx-sg-row">
            <CodeValue value="10.0.4.17" label="source address" />
            <CodeValue value="t13d1516h2_8daaf6152771_02713d6af862" label="JA4" />
            <TimeValue ts={1800000000} />
          </div>
          <div style={{ maxWidth: 520 }}>
            <Timeline
              items={[
                { ts: 1800000000, title: "Capture suspicious.pcap processed", detail: "13 flows, 1 above threshold (sample)" },
                { ts: 1800003600, title: "Alert raised", detail: "UNKNOWN_ANOMALY · confidence 0.45", colour: "var(--sev-low)" },
                { ts: 1800007200, title: "Analyst acknowledged", colour: "var(--ok)" },
              ]}
            />
          </div>
        </Section>

        <Section title="Banners and toasts">
          <div style={{ display: "grid", gap: 10 }}>
            <Banner title="Detector status">The detector is weak on real data today. Read the limitations before acting on a score.</Banner>
            <UntrainedBanner canTrain onTrain={() => {}} />
            <UntrainedBanner canTrain={false} />
            <StorageBanner retryAfter={10} onRetry={() => {}} />
            <Banner tone="error" title="Cannot reach the Spectra server">
              Check that the backend is running. Retrying in the background.
            </Banner>
          </div>
          <div className="sx-sg-row">
            {(["info", "ok", "warn", "error"] as const).map((tone) => (
              <SkewButton
                key={tone}
                variant="ghost"
                size="sm"
                onClick={() => setToasts((ts) => [...ts, { id: Date.now() + Math.random(), tone, text: `A ${tone} toast.` }])}
              >
                {tone} toast
              </SkewButton>
            ))}
          </div>
        </Section>

        <Section title="Loading, empty, error, permission">
          <div className="sx-sg-grid">
            <Card>
              <Loading />
            </Card>
            <Card>
              <EmptyState title="No alerts yet">Upload a capture or start a live capture. Alerts appear when a flow is unusual for this network.</EmptyState>
            </Card>
            <Card>
              <ErrorState detail="GET /api/alerts → 500" onRetry={() => {}} />
            </Card>
            <Card>
              <PermissionDenied permission="incidents:manage" what="acknowledge alerts" />
            </Card>
          </div>
        </Section>

        <Section title="DataTable" note="240 sample rows. Sortable headers, sticky header, scrolls inside its container, mono values with copy.">
          <SkewTabs
            label="Table state"
            value={tableState}
            onChange={setTableState}
            items={[
              { id: "data", label: "Data (paged)" },
              { id: "loading", label: "Loading" },
              { id: "empty", label: "Empty" },
              { id: "error", label: "Error" },
            ]}
          />
          <DataTable
            caption="Sample flows"
            columns={COLUMNS}
            rows={tableState === "data" ? SAMPLE_ROWS : tableState === "empty" ? [] : null}
            loading={tableState === "loading"}
            error={tableState === "error" ? "GET /api/flows → 503 storage temporarily unavailable" : null}
            rowKey={(r) => r.id}
            pageSize={10}
            onRowClick={() => setDrawer(true)}
            empty={{ title: "No flows yet", body: "Flows appear after a capture is processed." }}
          />
          <Eyebrow>Virtualised</Eyebrow>
          <DataTable caption="Sample flows, virtualised" columns={COLUMNS} rows={SAMPLE_ROWS} rowKey={(r) => r.id} virtual maxHeight={300} />
        </Section>

        <Section title="Overlays">
          <div className="sx-sg-row">
            <SkewButton variant="ghost" onClick={() => setModal(true)}>
              Open modal
            </SkewButton>
            <SkewButton variant="ghost" onClick={() => setConfirm(true)}>
              Open confirm dialog
            </SkewButton>
            <SkewButton variant="ghost" onClick={() => setDrawer(true)}>
              Open drawer
            </SkewButton>
          </div>
        </Section>

        <Section title="Art" note="All decorative (aria-hidden) and static under prefers-reduced-motion.">
          <div className="sx-sg-row" style={{ alignItems: "flex-end" }}>
            <HeroFocal />
            <SignalField />
            <LightBeam width={80} height={200} lines={12} />
            <GraphSample />
          </div>
          <div style={{ position: "relative", height: 160, background: "var(--bg-0)", borderRadius: 6, overflow: "hidden" }}>
            <DotGridBackground />
            <div style={{ position: "absolute", bottom: 0, left: 0, right: 0 }}>
              <Terrain height={120} />
            </div>
          </div>
        </Section>
      </main>

      <Modal
        open={modal}
        onClose={() => setModal(false)}
        title="Train a baseline"
        actions={
          <>
            <SkewButton variant="ghost" onClick={() => setModal(false)}>
              Cancel
            </SkewButton>
            <SkewButton onClick={() => setModal(false)}>Train</SkewButton>
          </>
        }
      >
        <Select label="Baseline capture" options={[{ value: "1", label: "baseline.pcap (sample)" }]} />
      </Modal>
      <ConfirmDialog
        open={confirm}
        title="Activate this model?"
        confirmLabel="Activate"
        onCancel={() => setConfirm(false)}
        onConfirm={() => setConfirm(false)}
        consequence="New flows are scored by this model from now on. Scores and alerts will not be comparable with those from the current model. You can roll back from the registry."
      />
      <Drawer open={drawer} onClose={() => setDrawer(false)} title="Flow detail (sample)">
        <div style={{ display: "grid", gap: 16 }}>
          <ScoreMeter score={97.4} threshold={90} />
          <KeyValue
            rows={[
              ["Source", <CodeValue value="10.0.4.17" />],
              ["Destination", <CodeValue value="192.0.2.10:443" />],
              ["Seen", <TimeValue ts={1800000000} />],
            ]}
          />
        </div>
      </Drawer>
      <Toasts items={toasts} onDismiss={(id) => setToasts((ts) => ts.filter((t) => t.id !== id))} />
    </div>
  );
}
