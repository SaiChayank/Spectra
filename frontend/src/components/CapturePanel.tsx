import { useCallback, useEffect, useState } from "react";
import {
  api,
  DuplicateCaptureError,
  type CaptureResource,
  type CaptureStatus,
} from "../lib/api";

interface Props {
  status: CaptureStatus;
  /** capture:manage + model:manage (ADMIN): import, start/stop, train. */
  canManage: boolean;
  onError: (msg: string | null) => void;
  onNotice: (msg: string | null) => void;
}

const STATUS_BADGE: Record<CaptureResource["status"], string> = {
  COMPLETED: "badge low",
  STOPPED: "badge low",
  UPLOADED: "badge mid",
  PROCESSING: "badge mid",
  FAILED: "badge high",
};

function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export default function CapturePanel({ status, canManage, onError, onNotice }: Props) {
  const [mode, setMode] = useState<"pcap" | "live">("pcap");
  const [pcapFile, setPcapFile] = useState<File | null>(null);
  const [iface, setIface] = useState("");
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [details, setDetails] = useState<
    { id: string; name: string; ip: string; description: string }[]
  >([]);
  const [trainFile, setTrainFile] = useState<File | null>(null);
  const [contamination, setContamination] = useState(0.05);
  const [captures, setCaptures] = useState<CaptureResource[]>([]);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    api
      .listCaptures(25)
      .then((r) => setCaptures(r.items))
      .catch(() => setCaptures([]));
  }, []);

  useEffect(() => {
    api
      .interfaces()
      .then((r) => {
        setInterfaces(r.interfaces);
        setDetails(r.details ?? []);
      })
      .catch(() => {
        setInterfaces([]);
        setDetails([]);
      });
    refresh();
    // A run starts/finishes by flipping `running`; refresh history on both.
  }, [status.running, refresh]);

  /** Import a file; identical content reuses its existing capture id. */
  const importOrReuse = async (file: File): Promise<{ id: number; note: string }> => {
    try {
      const resource = await api.importCapture(file);
      return {
        id: resource.capture_id,
        note: `Imported ${resource.original_name} as capture ${resource.capture_id}.`,
      };
    } catch (err) {
      if (err instanceof DuplicateCaptureError) {
        return {
          id: err.captureId,
          note: `Identical file already imported as capture ${err.captureId}.`,
        };
      }
      throw err;
    }
  };

  /** Import the selected PCAP and process it through detection. */
  const importAndRun = async () => {
    if (!pcapFile) return;
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      const { id, note } = await importOrReuse(pcapFile);
      await api.processCapture(id);
      onNotice(`${note} Processing…`);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const startLive = async () => {
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      await api.startCapture({ mode: "live", iface: iface || undefined });
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    try {
      await api.stopCapture();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  /** Import the baseline file (if any) and train on its capture id. */
  const train = async () => {
    if (!trainFile) return;
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      const { id } = await importOrReuse(trainFile);
      const info = await api.train(id, contamination);
      onNotice(`Model trained on ${info.n_train} flows → ${info.model_path}`);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const reprocess = async (captureId: number) => {
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      await api.processCapture(captureId);
      onNotice(`Capture ${captureId} reprocessing…`);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (captureId: number) => {
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      const out = await api.deleteCapture(captureId);
      onNotice(
        `Deleted capture ${out.deleted}` +
          (out.file_removed ? " (stored file removed)." : "."),
      );
      refresh();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid two-col">
      <section className="panel">
        <h2>Capture</h2>
        {!canManage && (
          <p className="note">
            Read-only role: importing PCAPs, starting captures and training
            require capture:manage / model:manage (ADMIN).
          </p>
        )}
        <div className="controls" style={canManage ? undefined : { display: "none" }}>
          <label>
            Source
            <select value={mode} onChange={(e) => setMode(e.target.value as "pcap" | "live")}>
              <option value="pcap">Import PCAP file</option>
              <option value="live">Live interface</option>
            </select>
          </label>

          {mode === "pcap" ? (
            <label style={{ flex: 1 }}>
              PCAP file (.pcap / .pcapng)
              <input
                type="file"
                accept=".pcap,.pcapng"
                onChange={(e) => setPcapFile(e.target.files?.[0] ?? null)}
              />
            </label>
          ) : (
            <label>
              Interface
              <select value={iface} onChange={(e) => setIface(e.target.value)}>
                <option value="">default</option>
                {details.length > 0
                  ? details.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                        {d.ip ? ` (${d.ip})` : ""}
                        {d.description && d.description !== d.name
                          ? ` — ${d.description}`
                          : ""}
                      </option>
                    ))
                  : interfaces.map((i) => (
                      <option key={i} value={i}>
                        {i}
                      </option>
                    ))}
              </select>
            </label>
          )}

          {!status.running ? (
            mode === "pcap" ? (
              <button onClick={importAndRun} disabled={busy || !pcapFile}>
                Import &amp; run
              </button>
            ) : (
              <button onClick={startLive} disabled={busy}>
                Start capture
              </button>
            )
          ) : (
            <button className="stop" onClick={stop} disabled={busy}>
              Stop capture
            </button>
          )}
        </div>

        <p className="note">
          {status.running
            ? `Capturing ${status.mode === "pcap" ? "from file" : "live from"} ${status.source}`
            : mode === "live"
              ? "Live capture requires Npcap (Windows) and an elevated shell."
              : pcapFile
                ? `${pcapFile.name} (${formatBytes(pcapFile.size)}) — the bytes are ` +
                  "uploaded and validated server-side; no path is ever typed."
                : "Choose a file: it is imported into the capture store, then processed."}
        </p>
      </section>

      <section className="panel">
        <h2>Model</h2>
        <div className="controls" style={canManage ? undefined : { display: "none" }}>
          <label style={{ flex: 1 }}>
            Baseline PCAP (benign)
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setTrainFile(e.target.files?.[0] ?? null)}
            />
          </label>
          <label>
            Contamination
            <input
              type="number"
              step="0.01"
              min="0.01"
              max="0.5"
              value={contamination}
              onChange={(e) => setContamination(Number(e.target.value))}
            />
          </label>
          <button onClick={train} disabled={busy || status.running || !trainFile}>
            Train
          </button>
        </div>
        <p className="note">
          {status.model_trained
            ? "Model ready — new flows are scored 0–100 with per-feature explanations."
            : "No model trained yet: flows are recorded but not scored."}
        </p>
      </section>

      <section className="panel" style={{ gridColumn: "1 / -1" }}>
        <h2>Capture history</h2>
        {captures.length === 0 ? (
          <p className="empty">No captures imported yet.</p>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 220 }}>
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Status</th>
                  <th>Size</th>
                  <th>Flows</th>
                  <th>Detections</th>
                  <th>Imported</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {captures.map((c) => (
                  <tr key={c.capture_id}>
                    <td title={c.original_name ?? undefined}>
                      {c.original_name ?? `capture ${c.capture_id}`}
                    </td>
                    <td>
                      <span className={STATUS_BADGE[c.status] ?? "badge mid"}>
                        {c.status}
                      </span>
                    </td>
                    <td>{formatBytes(c.size_bytes)}</td>
                    <td>{c.flows}</td>
                    <td>{c.detections}</td>
                    <td>
                      {c.imported_at
                        ? new Date(c.imported_at * 1000).toLocaleString()
                        : "—"}
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <button
                        onClick={() => reprocess(c.capture_id)}
                        disabled={busy || !canManage || status.running}
                        title={
                          canManage
                            ? "Process this capture again"
                            : "Requires capture:manage (ADMIN)"
                        }
                      >
                        {c.status === "UPLOADED" ? "Run" : "Run again"}
                      </button>{" "}
                      <button
                        className="stop"
                        onClick={() => remove(c.capture_id)}
                        disabled={busy || !canManage || c.running}
                        title={
                          !canManage
                            ? "Requires capture:manage (ADMIN)"
                            : c.running
                              ? "Cannot delete a capture while it runs"
                              : "Delete this capture and its stored file"
                        }
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="note">
          History is persisted server-side: statuses are UPLOADED → PROCESSING →
          COMPLETED / FAILED / STOPPED. Deleting removes the stored file; scored
          flow history is kept.
        </p>
      </section>
    </div>
  );
}
