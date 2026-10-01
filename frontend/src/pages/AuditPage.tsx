import { useState } from "react";
import {
  Empty,
  ErrorBox,
  KV,
  Locked,
  Loading,
  PageHeader,
  Pager,
} from "../components/states";
import {
  api,
  type AuditHead,
  type AuditPage,
  type AuditVerifyResult,
} from "../lib/api";
import { formatTs, relTime, shortHash } from "../lib/format";
import { useFetch } from "../lib/useFetch";

const PAGE_SIZE = 50;

interface Props {
  can: (permission: string) => boolean;
}

/** One-line human summary of an audit payload document. */
function payloadSummary(payload: Record<string, unknown>): string {
  const parts = Object.entries(payload)
    .filter(([, value]) => value == null || typeof value !== "object")
    .slice(0, 4)
    .map(([key, value]) => `${key}=${String(value)}`);
  const nested = Object.entries(payload)
    .filter(([, value]) => value != null && typeof value === "object")
    .map(([key]) => `${key}={…}`)
    .slice(0, 2);
  return [...parts, ...nested].join(" · ") || "—";
}

/**
 * Audit: the hash-chained action log (Module 5). Chain verification on
 * demand, head inspection, and filtered entry pages with full payloads.
 */
export default function AuditPage({ can }: Props) {
  const [kind, setKind] = useState("");
  const [actor, setActor] = useState("");
  const [offset, setOffset] = useState(0);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const allowed = can("investigate");

  const entries = useFetch<AuditPage>(
    () =>
      api.auditEntries({
        limit: PAGE_SIZE,
        offset,
        kind: kind.trim() || undefined,
        actor: actor.trim() || undefined,
      }),
    [offset, kind, actor],
    { enabled: allowed },
  );
  const head = useFetch<AuditHead>(() => api.auditHead(), [], {
    enabled: allowed,
    intervalMs: 30000,
  });

  const verify = async () => {
    setVerifying(true);
    try {
      setVerifyResult(await api.auditVerify());
    } catch {
      setVerifyResult({
        ok: false,
        entries: 0,
        head: { seq: 0, entry_hash: "", ts: null, kind: null },
        signing_key: null,
        errors: [{ seq: 0, reason: "verification request failed" }],
      });
    } finally {
      setVerifying(false);
    }
  };

  if (!allowed) {
    return (
      <>
        <PageHeader
          title="Audit"
          subtitle="Hash-chained record of every state-changing action."
        />
        <Locked
          permission="investigate"
          title="Audit trail is restricted"
          note="The audit log reveals who acted on what across the platform — it requires the “investigate” permission."
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Audit"
        subtitle="Hash-chained, actor-attributed action log — verify integrity, inspect payloads."
        actions={
          <button className="ghost" onClick={entries.reload}>
            Refresh
          </button>
        }
      />

      <div className="grid two-col" style={{ marginBottom: 16 }}>
        <section className="panel">
          <h2>Chain head</h2>
          {head.loading && !head.data && <Loading label="Loading head…" />}
          {head.error && <ErrorBox message={head.error} onRetry={head.reload} />}
          {head.data && (
            <>
              <KV k="sequence">{head.data.seq}</KV>
              <KV k="entry hash">
                <span className="mono">{head.data.entry_hash}</span>
              </KV>
              <KV k="last entry">
                {head.data.ts
                  ? `${head.data.kind ?? "—"} · ${formatTs(head.data.ts)}`
                  : "genesis"}
              </KV>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Integrity verification</h2>
          <p className="note">
            Re-walks the full chain: sequence continuity, prev-hash links and
            recomputed entry hashes.
          </p>
          <button disabled={verifying} onClick={verify}>
            {verifying ? "Verifying…" : "Verify chain"}
          </button>
          {verifyResult && (
            <div className="kv-list" style={{ marginTop: 10 }}>
              <KV k="result" verdict={verifyResult.ok ? "ok" : "bad"}>
                {verifyResult.ok
                  ? `intact — ${verifyResult.entries} entries verified`
                  : `${verifyResult.errors.length} problem(s) found`}
              </KV>
              <KV k="head">
                <span className="mono">
                  #{verifyResult.head.seq} {shortHash(verifyResult.head.entry_hash, 16)}
                </span>
              </KV>
              <KV k="signing key">
                <span className="mono">
                  {shortHash(verifyResult.signing_key ?? null, 24)}
                </span>
              </KV>
              {verifyResult.errors.map((error, index) => (
                <KV key={index} k={`seq ${error.seq}`} verdict="bad">
                  {error.reason}
                </KV>
              ))}
            </div>
          )}
        </section>
      </div>

      <section className="panel" style={{ marginBottom: 16 }}>
        <h2>Filters</h2>
        <div className="controls">
          <label>
            Kind
            <input
              value={kind}
              placeholder="model.activate"
              onChange={(e) => {
                setKind(e.target.value);
                setOffset(0);
              }}
            />
          </label>
          <label>
            Actor
            <input
              value={actor}
              placeholder="admin"
              onChange={(e) => {
                setActor(e.target.value);
                setOffset(0);
              }}
            />
          </label>
          <button
            className="ghost"
            onClick={() => {
              setKind("");
              setActor("");
              setOffset(0);
            }}
          >
            Clear
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>Entries {entries.data ? `(${entries.data.count} total)` : ""}</h2>
        {entries.loading && !entries.data && <Loading label="Loading entries…" />}
        {entries.error && (
          <ErrorBox message={entries.error} onRetry={entries.reload} />
        )}
        {entries.data && (
          <>
            {entries.data.items.length === 0 ? (
              <Empty
                message="No audit entries match"
                hint="Every state change writes here — clear the filters, or act on something."
              />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Seq</th>
                      <th>When</th>
                      <th>Kind</th>
                      <th>Actor</th>
                      <th>Payload</th>
                      <th>Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.data.items.map((entry) => (
                      <tr key={entry.seq}>
                        <td className="mono">{entry.seq}</td>
                        <td
                          className="dim"
                          title={`${formatTs(entry.ts)} · ${relTime(entry.ts)}`}
                        >
                          {relTime(entry.ts)}
                        </td>
                        <td>
                          <span className="tag">{entry.kind}</span>
                        </td>
                        <td>{entry.actor ?? "—"}</td>
                        <td>
                          <details>
                            <summary className="dim">
                              {payloadSummary(entry.payload)}
                            </summary>
                            <pre className="audit-payload">
                              {JSON.stringify(entry.payload, null, 2)}
                            </pre>
                          </details>
                        </td>
                        <td className="mono dim" title={entry.entry_hash}>
                          {shortHash(entry.entry_hash, 10)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager
              shown={entries.data.items.length}
              total={entries.data.count}
              offset={offset}
              limit={PAGE_SIZE}
              onChange={setOffset}
            />
          </>
        )}
      </section>
    </>
  );
}
