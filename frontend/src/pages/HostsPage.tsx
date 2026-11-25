import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Badge,
  Banner,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  KeyValue,
  Select,
  SkewButton,
  SkewTabs,
  Skeleton,
  Textarea,
  TimeValue,
  Timeline,
} from "../components/ui";
import { ApiError, api } from "../lib/api";
import type { HostEvidence, HostSummary, HostVerdict, HostVerdictValue } from "../lib/types";
import { useFetch } from "../lib/useFetch";

/**
 * Hosts: host-centric triage (GET /api/hosts, GET /api/hosts/{host}/evidence, POST /api/hosts/{host}/verdict).
 * Hosts are ranked by how much independent evidence the detectors raised; an analyst records a verdict per host.
 * The confidence is a ranking aid, NOT a calibrated probability, and the page says so.
 */

const VERDICTS: { value: HostVerdictValue; label: string; tone: "error" | "neutral" | "ok" }[] = [
  { value: "true", label: "True positive (malicious)", tone: "error" },
  { value: "expected", label: "Expected (benign, known)", tone: "neutral" },
  { value: "false", label: "False positive", tone: "ok" },
];
const verdictMeta = (v: HostVerdictValue) => VERDICTS.find((x) => x.value === v)!;
const DETECTOR_LABEL: Record<string, string> = { anomaly_model: "Anomaly model", beaconing: "Beaconing", intel: "Threat intel" };
const detectorName = (d: string) => DETECTOR_LABEL[d] ?? d;
const NOTE_MAX = 500; // backend VerdictRequest.note
/** Grid items default to min-width: auto, so the wide host table would stretch the page sideways instead of scrolling inside its own wrapper. */
const GRID_ITEM = { minWidth: 0 } as const;

function VerdictBadge({ verdict }: { verdict: HostVerdict | null }) {
  if (!verdict) return <span className="sx-hint">No verdict</span>;
  const m = verdictMeta(verdict.verdict);
  return <Badge tone={m.tone}>{m.label.split(" (")[0]}</Badge>;
}

interface Props {
  /** Recording a verdict needs incidents:manage (ADMIN, ANALYST). */
  canTriage: boolean;
}

export default function HostsPage({ canTriage }: Props) {
  const [sort, setSort] = useState<"risk" | "last_seen">("risk");
  const [selected, setSelected] = useState<string | null>(null);
  const list = useFetch(() => api.hosts(sort), [sort], { intervalMs: 30_000 });

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Banner title="How hosts are ranked">
        Each host is ranked by the evidence Spectra's detectors raised against it. The confidence orders the list; it is not a
        probability that the host is compromised. Record a verdict once you have looked, so the next shift knows.
      </Banner>
      <SkewTabs
        label="Order hosts by"
        value={sort}
        onChange={setSort}
        items={[
          { id: "risk", label: "Highest risk" },
          { id: "last_seen", label: "Most recent" },
        ]}
      />
      <div style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 420px), 1fr))" }}>
        <Card style={GRID_ITEM} title="Hosts" eyebrow={list.data ? `${list.data.count} with evidence` : "Triage"}>
          <DataTable<HostSummary>
            caption="Hosts ranked by evidence"
            rows={list.data?.items ?? null}
            loading={list.loading}
            error={list.error}
            onRetry={list.reload}
            rowKey={(h) => h.host}
            onRowClick={(h) => setSelected(h.host)}
            selectedKey={selected}
            empty={{ title: "No host has evidence yet", body: "Hosts appear here once a detector raises an alert on their traffic." }}
            columns={[
              { key: "rank", header: "#", sort: (h) => h.rank, align: "right", width: 48 },
              { key: "host", header: "Host", sort: (h) => h.host, code: (h) => h.host },
              { key: "confidence", header: "Confidence", sort: (h) => h.confidence, align: "right",
                render: (h) => `${Math.round(h.confidence * 100)}%` },
              { key: "evidence_count", header: "Evidence", sort: (h) => h.evidence_count, align: "right" },
              { key: "top", header: "Strongest signal", render: (h) => detectorName(h.top_evidence.detector) },
              { key: "last_seen", header: "Last seen", sort: (h) => h.last_seen, render: (h) => <TimeValue ts={h.last_seen} /> },
              { key: "verdict", header: "Verdict", render: (h) => <VerdictBadge verdict={h.verdict} /> },
            ]}
          />
        </Card>
        {selected ? (
          <HostDetail key={selected} host={selected} canTriage={canTriage} onSaved={list.reload} onClose={() => setSelected(null)} />
        ) : (
          <Card style={GRID_ITEM} title="Host detail">
            <EmptyState title="Select a host">Pick a host in the list to see its evidence and record a verdict.</EmptyState>
          </Card>
        )}
      </div>
    </div>
  );
}

function HostDetail({ host, canTriage, onSaved, onClose }: { host: string; canTriage: boolean; onSaved: () => void; onClose: () => void }) {
  const ev = useFetch(() => api.hostEvidence(host), [host]);
  const ref = useRef<HTMLDivElement>(null);
  // on a phone the detail stacks below the list: bring it into view (no jump on wide screens, where it is beside it)
  useEffect(() => {
    ref.current?.scrollIntoView?.({ block: "nearest", behavior: "smooth" }); // braces: never return its result as a cleanup
  }, []);
  return (
    <div ref={ref} style={GRID_ITEM}>
    <Card title={host} eyebrow="Host detail" actions={<SkewButton variant="ghost" onClick={onClose}>Close</SkewButton>}>
      {ev.loading ? (
        <Skeleton lines={4} />
      ) : ev.error ? (
        <ErrorState detail={ev.error} onRetry={ev.reload} />
      ) : ev.data ? (
        <div style={{ display: "grid", gap: 16 }}>
          <Evidence data={ev.data} />
          <VerdictForm host={host} current={ev.data.verdict} canTriage={canTriage} onSaved={() => { ev.reload(); onSaved(); }} />
        </div>
      ) : null}
    </Card>
    </div>
  );
}

function Evidence({ data }: { data: HostEvidence }) {
  if (data.items.length === 0) return <EmptyState title="No evidence">This host has no open evidence.</EmptyState>;
  return (
    <section aria-label="Evidence timeline">
      <Timeline
        items={[...data.items].sort((a, b) => b.time - a.time).map((e) => ({
          ts: e.time,
          title: `${detectorName(e.detector)}: ${e.threat_type.replace(/_/g, " ").toLowerCase()}`,
          detail: (
            <>
              to <code>{e.destination}</code> · seen {e.occurrences}× · strength {Math.round(e.strength * 100)}% · alert{" "}
              <code>{e.alert_id}</code>
            </>
          ),
        }))}
      />
    </section>
  );
}

function VerdictForm({ host, current, canTriage, onSaved }: {
  host: string; current: HostVerdict | null; canTriage: boolean; onSaved: () => void;
}) {
  const [verdict, setVerdict] = useState<HostVerdictValue>(current?.verdict ?? "true");
  const [note, setNote] = useState(current?.note ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await api.setHostVerdict(host, verdict, note.trim() || undefined);
      setSaved(true);
      onSaved();
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) setError("Your role cannot record verdicts.");
      else if (err instanceof ApiError && err.status === 404) setError("This host no longer has evidence.");
      else setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-label="Host verdict" style={{ display: "grid", gap: 12 }}>
      {current ? (
        <KeyValue rows={[
          ["Current verdict", <VerdictBadge key="v" verdict={current} />],
          ["Recorded by", current.actor],
          ["When", <TimeValue key="t" ts={current.created_at} />],
          ...(current.note ? [["Note", current.note] as [string, string]] : []),
        ]} />
      ) : null}
      {canTriage ? (
        <form onSubmit={submit} style={{ display: "grid", gap: 12 }} noValidate>
          <Select label="Verdict" value={verdict} onChange={(e) => setVerdict(e.target.value as HostVerdictValue)}
            options={VERDICTS.map((v) => ({ value: v.value, label: v.label }))} />
          <Textarea label="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={NOTE_MAX} rows={3}
            hint={`${note.length}/${NOTE_MAX}. Visible to everyone who can read this host; do not paste secrets.`} />
          {error ? <Banner tone="error" title="Verdict not saved">{error}</Banner> : null}
          {saved ? <Banner tone="info" title="Verdict saved">It is recorded in the audit log.</Banner> : null}
          <div>
            <SkewButton type="submit" loading={busy}>{current ? "Update verdict" : "Record verdict"}</SkewButton>
          </div>
        </form>
      ) : (
        <p className="sx-hint">Your role can read hosts but not record verdicts (needs an analyst or administrator).</p>
      )}
    </section>
  );
}
