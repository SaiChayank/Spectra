import { useCallback, useState } from "react";
import CapabilityStrip from "./CapabilityStrip";
import { api, type FederateResult, type TeeQuote, type TeeVerifyResult } from "../lib/api";

const shortId = () =>
  `ui-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

/** Clearly-labelled demo deltas for the federated round (3 parties × 3 dims). */
const DEMO_DELTAS = [
  [0.12, -0.04, 0.31],
  [0.07, 0.15, -0.09],
  [-0.03, 0.22, 0.44],
];

export default function TeePanel({ canRun, onError, onNotice }: {
  /** investigate permission (ANALYST/ADMIN): attest, verify, federate. */
  canRun: boolean;
  onError: (msg: string) => void;
  onNotice: (msg: string) => void;
}) {
  const [nonce, setNonce] = useState(shortId);
  const [busy, setBusy] = useState(false);
  const [quote, setQuote] = useState<TeeQuote | null>(null);
  const [verify, setVerify] = useState<TeeVerifyResult | null>(null);
  const [federated, setFederated] = useState<FederateResult | null>(null);

  const attest = useCallback(async () => {
    setBusy(true);
    try {
      setQuote(await api.teeAttest(nonce || null));
      setVerify(null);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [nonce, onError]);

  const runVerify = useCallback(async () => {
    if (!quote) return;
    setBusy(true);
    try {
      setVerify(await api.teeVerify(quote, nonce || null));
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [quote, nonce, onError]);

  const runFederate = useCallback(async () => {
    setBusy(true);
    try {
      setFederated(await api.teeFederate({ deltas: DEMO_DELTAS, shareholders: 3, seed: 7 }));
      onNotice("Federated round complete — coordinator saw the sum of updates only.");
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [onError, onNotice]);

  return (
    <div className="grid two-col">
      <div style={{ gridColumn: "1 / -1" }}>
        {/* data-driven maturity badges (GET /api/capabilities): SIMULATED
            is labelled by the contract, not by a hardcoded sentence */}
        <CapabilityStrip keys={["tee", "federated"]} />
        <p className="note">
          Attestation, sealed inference and federated rounds run in-process; per-party secret
          shares never leave the backend.
          {!canRun && " Running them requires the investigate permission."}
        </p>
      </div>
      <section className="panel">
        <h2>Attestation quote</h2>
        <div className="controls" style={{ marginBottom: 12 }}>
          <label>
            Challenge nonce
            <input value={nonce} onChange={(e) => setNonce(e.target.value)} spellCheck={false} />
          </label>
          <button
            onClick={attest}
            disabled={busy || !canRun}
            style={{ alignSelf: "flex-end" }}
            title={canRun ? undefined : "Requires investigate (ANALYST/ADMIN)"}
          >
            Attest
          </button>
        </div>
        {!quote ? (
          <div className="empty">
            No quote yet — attest to bind a nonce to the model measurement.
          </div>
        ) : (
          <>
            <div className="kv">
              <span className="k">Measurement</span>
              <span className="v mono" title={quote.measurement}>
                {quote.measurement.slice(0, 24)}…
              </span>
            </div>
            <div className="kv">
              <span className="k">Issued</span>
              <span className="v">{new Date(quote.ts * 1000).toLocaleString()}</span>
            </div>
            <div className="kv">
              <span className="k">Nonce</span>
              <span className="v mono">{quote.nonce ?? "—"}</span>
            </div>
            <div className="kv">
              <span className="k">Issuer key</span>
              <span className="v mono" title={quote.pubkey}>
                {quote.pubkey.slice(0, 20)}…
              </span>
            </div>
            <div className="kv">
              <span className="k">Schnorr signature</span>
              <span className="v mono" title={quote.signature}>
                {quote.signature.slice(0, 28)}…
              </span>
            </div>
            <div className="controls" style={{ marginTop: 12 }}>
              <button onClick={runVerify} disabled={busy || !canRun}>
                Verify quote
              </button>
              <button className="ghost" onClick={attest} disabled={busy || !canRun}>
                Re-attest
              </button>
            </div>
          </>
        )}
      </section>

      <section className="panel">
        <h2>Verification</h2>
        {!verify ? (
          <div className="empty">Verify a quote to see its seven checks.</div>
        ) : (
          <>
            <div className={`kv verdict ${verify.ok ? "ok" : "bad"}`}>
              <span className="k">Result</span>
              <span className="v">{verify.ok ? "VERIFIED" : "REJECTED"}</span>
            </div>
            {verify.checks.map((c) => (
              <div className="kv" key={c.name}>
                <span className="k">
                  <span className={c.ok ? "check-ok" : "check-bad"}>{c.ok ? "✓" : "✗"}</span>{" "}
                  {c.name}
                </span>
                <span className="v dim">{c.detail}</span>
              </div>
            ))}
            <div className="kv">
              <span className="k">Quote age</span>
              <span className="v">{verify.age_s.toFixed(1)}s</span>
            </div>
            <div className="kv">
              <span className="k">Measurement match</span>
              <span className="v">
                {verify.measurement === verify.expected_measurement ? "current model" : "MISMATCH"}
              </span>
            </div>
          </>
        )}
      </section>

      <section className="panel" style={{ gridColumn: "1 / -1" }}>
        <h2>Federated round (k-of-k additive sharing)</h2>
        <div className="controls" style={{ marginBottom: 12 }}>
          <button onClick={runFederate} disabled={busy || !canRun}>
            Run demo round
          </button>
          <span className="dim" style={{ fontSize: 12 }}>
            3 parties × 3 shareholders over demo deltas
          </span>
        </div>
        {!federated ? (
          <div className="empty">No round yet — run one to see secret sharing in action.</div>
        ) : (
          <>
            <div className="kv">
              <span className="k">Exact recombination</span>
              <span className="v">{federated.exact ? "✓ true" : "✗ false"}</span>
            </div>
            <div className="kv">
              <span className="k">Aggregate (first 3)</span>
              <span className="v mono">
                [{federated.aggregate.slice(0, 3).map((x) => x.toFixed(3)).join(", ")}]
              </span>
            </div>
            <div className="kv">
              <span className="k">Shares issued</span>
              <span className="v">
                {federated.parties} parties × {federated.shareholders} shareholders · dim{" "}
                {federated.dim} · quantize 1e{Math.log10(federated.quantize)}
              </span>
            </div>
            <div className="kv">
              <span className="k">Raw data egress</span>
              <span className="v">{String(federated.claims.raw_data_egress ?? 0)} bytes</span>
            </div>
            <div className="kv">
              <span className="k">Coordinator learns</span>
              <span className="v">{String(federated.claims.learned_by_coordinator ?? "—")}</span>
            </div>
            <p className="note">
              Each party secret-shares its update; only the summed aggregate is reconstructible.
              Privacy holds while fewer than {federated.shareholders} shareholders collude.
            </p>
          </>
        )}
      </section>
    </div>
  );
}
