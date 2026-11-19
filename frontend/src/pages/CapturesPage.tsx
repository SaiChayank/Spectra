import { useCallback, useEffect, useState } from "react";
import {
  Badge,
  Banner,
  Card,
  ConfirmDialog,
  DataTable,
  FileDrop,
  Input,
  KeyValue,
  PermissionDenied,
  Select,
  SkewButton,
  StatusPill,
  TimeValue,
  Tooltip,
  type Column,
  type Status,
} from "../components/ui";
import { ApiError, DuplicateCaptureError, api, type CaptureResource, type CaptureStatus, type ModelInfo } from "../lib/api";
import { scoreThreshold } from "./AlertsPage";

const STATUS: Record<CaptureResource["status"], Status> = {
  UPLOADED: "idle",
  PROCESSING: "live",
  COMPLETED: "ok",
  FAILED: "error",
  STOPPED: "idle",
};

const bytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const msg = (err: unknown) => (err instanceof Error ? err.message : String(err));

interface Props {
  can: (permission: string) => boolean;
  capture: CaptureStatus | undefined;
  model: ModelInfo | undefined;
  /** Re-read stats/status after an action (shell banners, pills). */
  onChanged: () => void;
}

/** Captures & model (P0-3): upload, process, live capture, and the model that scores them. */
export default function CapturesPage({ can, capture, model, onChanged }: Props) {
  const canCapture = can("capture:manage");
  const canTrain = can("model:manage");
  const [rows, setRows] = useState<CaptureResource[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [uploading, setUploading] = useState(false);
  const [notice, setNotice] = useState<{ tone: "info" | "warn" | "error"; text: string } | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [toDelete, setToDelete] = useState<CaptureResource | null>(null);
  const [trainOpen, setTrainOpen] = useState(false);
  const [baseline, setBaseline] = useState("");
  const [contamination, setContamination] = useState("0.02");
  const [training, setTraining] = useState(false);

  const load = useCallback(() => {
    api
      .listCaptures(200)
      .then((r) => {
        setRows(r.items);
        setLoadError(null);
      })
      .catch((e: unknown) => setLoadError(e));
  }, []);
  useEffect(load, [load]);

  const after = (n: { tone: "info" | "warn" | "error"; text: string }) => {
    setNotice(n);
    load();
    onChanged();
  };

  const upload = async (file: File) => {
    setUploading(true);
    setNotice(null);
    try {
      const c = await api.importCapture(file);
      after({ tone: "info", text: `Imported ${c.original_name ?? "capture"} as #${c.capture_id}. Process it to parse and score its flows.` });
    } catch (err) {
      if (err instanceof DuplicateCaptureError) after({ tone: "warn", text: `This file is already imported as capture #${err.captureId}.` });
      else setNotice({ tone: "error", text: msg(err) });
    } finally {
      setUploading(false);
    }
  };

  const process = async (c: CaptureResource) => {
    setBusyId(c.capture_id);
    try {
      const out = await api.processCapture(c.capture_id);
      const unscored = out.unscored_flows ?? 0;
      after(
        unscored > 0
          ? { tone: "warn", text: `Processed #${c.capture_id}: ${out.flows} flows, but ${unscored} are unscored because no model is trained. Zero detections here means nothing.` }
          : { tone: "info", text: `Processed #${c.capture_id}: ${out.flows} flows, ${out.detections} above the threshold.` },
      );
    } catch (err) {
      setNotice({ tone: "error", text: `Processing #${c.capture_id} failed: ${msg(err)}` });
    } finally {
      setBusyId(null);
    }
  };

  const remove = async () => {
    if (!toDelete) return;
    setBusyId(toDelete.capture_id);
    try {
      await api.deleteCapture(toDelete.capture_id);
      setToDelete(null);
      after({ tone: "info", text: `Deleted capture #${toDelete.capture_id}.` });
    } catch (err) {
      setNotice({ tone: "error", text: msg(err) });
      setToDelete(null);
    } finally {
      setBusyId(null);
    }
  };

  const completed = (rows ?? []).filter((c) => c.status === "COMPLETED");
  const contaminationValue = Number(contamination);
  const contaminationOk = contaminationValue > 0 && contaminationValue < 0.5;

  const train = async () => {
    setTraining(true);
    try {
      const out = await api.train(Number(baseline), contaminationValue, true);
      setTrainOpen(false);
      after({
        tone: "info",
        text: `Trained on ${out.n_train} flows${out.registry && !out.registry.activated ? " as a candidate (not active yet: see Models)" : " and activated"}. Process captures again to score them with it.`,
      });
    } catch (err) {
      setTrainOpen(false);
      setNotice({ tone: "error", text: `Training failed: ${msg(err)}` });
    } finally {
      setTraining(false);
    }
  };

  const threshold = scoreThreshold(model);

  const columns: Column<CaptureResource>[] = [
    { key: "id", header: "#", align: "right", sort: (c) => c.capture_id, render: (c) => c.capture_id },
    { key: "name", header: "File", sort: (c) => c.original_name, render: (c) => c.original_name ?? <span className="sx-hint">{c.source_type}</span> },
    {
      key: "status",
      header: "Status",
      sort: (c) => c.status,
      render: (c) => (
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          <StatusPill status={STATUS[c.status]}>{c.status.toLowerCase()}</StatusPill>
          {(c.unscored_flows ?? 0) > 0 ? (
            <Tooltip tip={`${c.unscored_flows} of ${c.flows} flows were stored without a score (no trained model).`}>
              <Badge tone="warn">Unscored</Badge>
            </Tooltip>
          ) : null}
        </span>
      ),
    },
    { key: "size", header: "Size", align: "right", sort: (c) => c.size_bytes, render: (c) => bytes(c.size_bytes) },
    { key: "flows", header: "Flows", align: "right", sort: (c) => c.flows, render: (c) => c.flows.toLocaleString() },
    { key: "det", header: "Above threshold", align: "right", sort: (c) => c.detections, render: (c) => c.detections.toLocaleString() },
    { key: "imported", header: "Imported", sort: (c) => c.imported_at, render: (c) => (c.imported_at ? <TimeValue ts={c.imported_at} /> : "—") },
    ...(canCapture
      ? [
          {
            key: "act",
            header: "Actions",
            render: (c: CaptureResource) => (
              <span style={{ display: "inline-flex", gap: 6 }}>
                <SkewButton size="sm" variant="ghost" loading={busyId === c.capture_id} disabled={c.running} onClick={() => process(c)} aria-label={`Process capture ${c.capture_id}`}>
                  {c.status === "COMPLETED" ? "Reprocess" : "Process"}
                </SkewButton>
                <SkewButton size="sm" variant="danger" disabled={c.running} onClick={() => setToDelete(c)} aria-label={`Delete capture ${c.capture_id}`}>
                  Delete
                </SkewButton>
              </span>
            ),
          } as Column<CaptureResource>,
        ]
      : []),
  ];

  return (
    <div style={{ display: "grid", gap: 18 }}>
      {notice ? (
        <Banner
          tone={notice.tone}
          title={notice.tone === "error" ? "Not done" : notice.tone === "warn" ? "Note" : "Done"}
          action={
            <SkewButton size="sm" variant="ghost" onClick={() => setNotice(null)}>
              Dismiss
            </SkewButton>
          }
        >
          {notice.text}
        </Banner>
      ) : null}

      <div style={{ display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 380px), 1fr))", alignItems: "start" }}>
        <Card
          title="Detection model"
          eyebrow="Scores every flow"
          actions={<StatusPill status={model?.trained ? "ok" : "warn"}>{model?.trained ? "Trained" : "Not trained"}</StatusPill>}
        >
          {model?.trained ? (
            <KeyValue
              rows={[
                ["Trained on", `${model.n_train.toLocaleString()} flows`],
                ["Trained at", model.trained_at && !Number.isNaN(Date.parse(model.trained_at)) ? <TimeValue ts={Date.parse(model.trained_at) / 1000} /> : (model.trained_at ?? "—")],
                ["Flags flows above", threshold !== null ? <span className="sx-mono">{threshold} / 100</span> : "—"],
                ["Contamination", <span className="sx-mono">{model.contamination}</span>],
                ["Features", model.n_features],
              ]}
            />
          ) : (
            <p>
              Nothing is scored until a model learns what normal looks like on <em>your</em> network. Train it on a capture of known-good
              traffic.
            </p>
          )}
          <div style={{ marginTop: 14 }}>
            {canTrain ? (
              <SkewButton variant={model?.trained ? "ghost" : "primary"} disabled={completed.length === 0} onClick={() => {
                setBaseline(String(completed[0]?.capture_id ?? ""));
                setTrainOpen(true);
              }}>
                {model?.trained ? "Retrain" : "Train a baseline"}
              </SkewButton>
            ) : (
              <span className="sx-hint">Training needs the model:manage permission.</span>
            )}
            {canTrain && completed.length === 0 ? <p className="sx-hint" style={{ marginTop: 8 }}>Upload and process a capture first.</p> : null}
          </div>
        </Card>

        <Card title="Upload a capture" eyebrow="PCAP / PCAPNG">
          {canCapture ? (
            <div style={{ display: "grid", gap: 8 }}>
              <FileDrop onFile={upload} disabled={uploading} label={uploading ? "Uploading…" : undefined} />
              {uploading ? <p role="status" className="sx-hint">Uploading and stripping payload bytes…</p> : null}
            </div>
          ) : (
            <PermissionDenied permission="capture:manage" what="upload captures" />
          )}
        </Card>

        <LiveCapture canCapture={canCapture} capture={capture} onChanged={onChanged} />
      </div>

      {loadError instanceof ApiError && loadError.status === 403 ? (
        <PermissionDenied permission="read" what="list captures" />
      ) : (
        <DataTable
          caption="Captures"
          columns={columns}
          rows={rows}
          loading={rows === null && !loadError}
          error={loadError ? msg(loadError) : null}
          onRetry={load}
          rowKey={(c) => c.capture_id}
          initialSort={{ key: "id", dir: "desc" }}
          empty={{ title: "No captures yet", body: "Upload a PCAP above, or start a live capture." }}
        />
      )}

      <ConfirmDialog
        open={toDelete !== null}
        title={toDelete ? `Delete capture #${toDelete.capture_id}?` : "Delete capture?"}
        confirmLabel="Delete capture"
        danger
        busy={busyId === toDelete?.capture_id}
        onCancel={() => setToDelete(null)}
        onConfirm={remove}
        consequence="The stored file and its record are removed. Flows and alerts already derived from it stay until retention removes them."
      />

      <ConfirmDialog
        open={trainOpen}
        title="Train a new baseline model?"
        confirmLabel="Train"
        busy={training}
        onCancel={() => setTrainOpen(false)}
        onConfirm={() => contaminationOk && baseline && void train()}
        consequence="The model learns 'normal' from this capture and, if the registry allows, becomes active: new flows are scored by it, and scores are not comparable with the previous model's. Train only on traffic you believe is benign."
      >
        <div style={{ display: "grid", gap: 12 }}>
          <Select
            label="Baseline capture (known-good traffic)"
            value={baseline}
            onChange={(e) => setBaseline(e.target.value)}
            options={completed.map((c) => ({ value: String(c.capture_id), label: `#${c.capture_id} · ${c.original_name ?? c.source_type} · ${c.flows} flows` }))}
          />
          <Input
            label="Contamination"
            value={contamination}
            onChange={(e) => setContamination(e.target.value)}
            inputMode="decimal"
            hint="Share of baseline flows treated as unusual. 0.02 flags the top 2 %."
            error={contaminationOk ? undefined : "Use a number between 0 and 0.5."}
          />
        </div>
      </ConfirmDialog>
    </div>
  );
}

function LiveCapture({ canCapture, capture, onChanged }: { canCapture: boolean; capture: CaptureStatus | undefined; onChanged: () => void }) {
  const [ifaces, setIfaces] = useState<string[] | null>(null);
  const [ifaceError, setIfaceError] = useState<string | null>(null);
  const [iface, setIface] = useState("");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = capture?.running && capture.mode === "live";

  useEffect(() => {
    if (!canCapture) return;
    api
      .interfaces()
      .then((r) => {
        setIfaces(r.interfaces);
        setIface((cur) => cur || r.interfaces[0] || "");
        if (r.error) setIfaceError(r.error);
      })
      .catch((e: unknown) => setIfaceError(msg(e)));
  }, [canCapture]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (err) {
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Live capture" eyebrow="Network interface" actions={<StatusPill status={capture?.error ? "error" : live ? "live" : "idle"}>{capture?.error ? "Error" : live ? "Capturing" : "Stopped"}</StatusPill>}>
      {capture?.error ? (
        <Banner tone="error" title="Capture error">
          {capture.error} A capture that started can stop a second later; check the interface and permissions.
        </Banner>
      ) : null}
      {!canCapture ? (
        <PermissionDenied permission="capture:manage" what="start a live capture" />
      ) : live ? (
        <div style={{ display: "grid", gap: 12 }}>
          <KeyValue
            rows={[
              ["Interface", capture?.source],
              ["Packets", capture?.packets.toLocaleString()],
              ["Flows", capture?.flows.toLocaleString()],
              ["Started", capture?.started_at ? <TimeValue ts={capture.started_at} /> : null],
            ]}
          />
          <div>
            <SkewButton variant="danger" loading={busy} onClick={() => run(() => api.stopCapture())}>
              Stop capture
            </SkewButton>
          </div>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 12, marginTop: capture?.error ? 12 : 0 }}>
          {ifaceError ? <p className="sx-hint">Interfaces: {ifaceError}</p> : null}
          <Select
            label="Interface"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            disabled={!ifaces || ifaces.length === 0}
            options={(ifaces ?? []).map((i) => ({ value: i, label: i }))}
          />
          <Input label="Filter (BPF, optional)" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="tcp port 443" className="sx-input sx-mono" />
          {error ? (
            <Banner tone="error" title="Not started">
              {error}
            </Banner>
          ) : null}
          <div>
            <SkewButton
              loading={busy}
              disabled={!iface}
              onClick={() => run(() => api.startCapture({ mode: "live", iface, bpf_filter: filter.trim() || undefined }))}
            >
              Start capture
            </SkewButton>
          </div>
          <p className="sx-hint">Passive: Spectra only listens. Needs capture privileges on the server (Npcap on Windows).</p>
        </div>
      )}
    </Card>
  );
}
