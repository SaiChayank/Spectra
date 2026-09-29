import { useEffect, useState } from "react";
import { api, type CaptureStatus } from "../lib/api";

interface Props {
  status: CaptureStatus;
  onError: (msg: string | null) => void;
  onNotice: (msg: string | null) => void;
}

export default function CapturePanel({ status, onError, onNotice }: Props) {
  const [mode, setMode] = useState<"pcap" | "live">("pcap");
  const [path, setPath] = useState("data/demo/suspicious.pcap");
  const [iface, setIface] = useState("");
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [trainPath, setTrainPath] = useState("data/demo/baseline.pcap");
  const [contamination, setContamination] = useState(0.05);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .interfaces()
      .then((r) => setInterfaces(r.interfaces))
      .catch(() => setInterfaces([]));
  }, [status.running]);

  const start = async () => {
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      await api.startCapture(
        mode === "pcap" ? { mode, path } : { mode, iface: iface || undefined },
      );
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

  const train = async () => {
    onError(null);
    onNotice(null);
    setBusy(true);
    try {
      const info = await api.train(trainPath, contamination);
      onNotice(`Model trained on ${info.n_train} flows → ${info.model_path}`);
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
        <div className="controls">
          <label>
            Source
            <select value={mode} onChange={(e) => setMode(e.target.value as "pcap" | "live")}>
              <option value="pcap">PCAP file</option>
              <option value="live">Live interface</option>
            </select>
          </label>

          {mode === "pcap" ? (
            <label style={{ flex: 1 }}>
              PCAP path
              <input value={path} onChange={(e) => setPath(e.target.value)} />
            </label>
          ) : (
            <label>
              Interface
              <select value={iface} onChange={(e) => setIface(e.target.value)}>
                <option value="">default</option>
                {interfaces.map((i) => (
                  <option key={i} value={i}>
                    {i}
                  </option>
                ))}
              </select>
            </label>
          )}

          {!status.running ? (
            <button onClick={start} disabled={busy || (mode === "pcap" && !path)}>
              Start capture
            </button>
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
              : "Flows are scored as the capture completes them."}
        </p>
      </section>

      <section className="panel">
        <h2>Model</h2>
        <div className="controls">
          <label style={{ flex: 1 }}>
            Baseline PCAP (benign)
            <input value={trainPath} onChange={(e) => setTrainPath(e.target.value)} />
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
          <button onClick={train} disabled={busy || status.running}>
            Train
          </button>
        </div>
        <p className="note">
          {status.model_trained
            ? "Model ready — new flows are scored 0–100 with per-feature explanations."
            : "No model trained yet: flows are recorded but not scored."}
        </p>
      </section>
    </div>
  );
}
