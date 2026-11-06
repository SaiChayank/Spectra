# Spectra — Ship Plan (v1.0 public release)

Status: **DRAFT, written 2026-11-06.** It needs the owner's review. It extends
`docs/33_implementation_plan.md` Part II and `HANDOFF.md` Phases 9–12. It does
not replace them, and every HANDOFF rule (R1–R41) still binds. Items marked
**[DECISION]** are the owner's call. Items marked **[HUMAN]** need a person:
a sign-off, a review, an account or a payment.

---

## 0. What "ship to the internet" means here

Spectra ships as **self-hosted software**. It is a passive sensor and has to
sit on the network it watches, so users install and run it themselves. We
host nothing that processes anyone's traffic.

Release channels:
- a container image on GHCR (multi-arch), plus a compose file,
- a wheel on PyPI (`pip install` → `spectra serve`),
- GitHub Releases (signed artifacts, SBOM, release notes),
- a docs site on GitHub Pages.

**Out of scope:**
- **A hosted demo or SaaS.** HANDOFF's definition of "industry grade"
  excludes internet-facing multi-tenant SaaS, and it would reopen the DPIA
  (12C). The "try it" path is local instead: `spectra demo` and the synthetic
  demo captures run on the user's machine.
- **Telemetry or phone-home.** Spectra makes no outbound connections. That
  fits the metadata-only promise and is a selling point.

**Cost target: $0.** Every tool and dataset below is free. GitHub Pages,
GHCR, PyPI and Actions are free for a public repo.

---

## 1. Where the project actually stands (2026-11-06)

| Area | State |
|---|---|
| Phases 0–8, Gate 8.5 | Done; approved by the owner |
| 9A windowed correlation | Done (local branch, unpushed) |
| 9B adversarial retraining | **Gate only.** The "Done-when" is NOT MET: augmentation does not reduce evasion (HANDOFF_FINDINGS 9B) |
| 9C synthetic benign | Done, **synthetic held-out only.** The real-traffic comparison was NOT RUN |
| 9D–9H | Not started |
| Real-dataset evaluation | **No report exists.** The eval harness (`spectra eval`, `datasets.py`, CTU-13/CICIDS adapters) is built but has never produced a recorded run |
| Phase 10 security evidence | Not started; there is no `docs/evidence/` |
| Phase 11 ops | No Dockerfile, no published wheel, no Prometheus exposition |
| Repo hygiene | No `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md` or `CHANGELOG.md`. `CLAUDE.md`/`HANDOFF.md` cite `docs/16`/`docs/17`, which `main` deleted |

The biggest gap for a public release is the honest accuracy number, not
features. Every claim on the docs site must come from §3's benchmark runs.

---

## 2. Phase order and gates

```
S0 housekeeping ─► 9D..9H ─► B (benchmarks) ─► 10 (security) ─► 11 (packaging/ops) ─► 13 (release)
                                  ▲                                                     │
                                  └────────── nightly bench in CI feeds ────────────────┘
```

| Phase | Size | Gate (evidence required) |
|---|---|---|
| S0 Housekeeping | S | Branches pushed and PRs open; dead doc refs fixed; LICENSE chosen |
| 9D–9H | L | As in docs/33; Exit Gate 9 acceptance run saved |
| **B Benchmarks** (new; it delivers 10.4) | L | `docs/evaluation-report.md` built from recorded runs on ≥ 3 public datasets, each with hashes and confidence intervals |
| 10 Security | L | Raw scan outputs in `docs/evidence/<date>/`; zero open Critical/High; TOTP and lockout tests green; **[HUMAN] security review** |
| 11 Packaging / ops | M | Clean install works on every supported platform; image built and scanned; upgrade from the previous release tested; restore drill logged |
| **13 Release** (new) | M | Docs site live; v1.0.0 artifacts signed; a fresh machine installs Spectra from the docs alone |
| 12 Scale-out | — | Only on a per-item instruction (unchanged) |

---

## S0. Housekeeping (do first, small)

1. Push `phase9a/…`, `phase9b/…` and `phase9c/…`, then open stacked PRs (or
   merge PR #1 first and rebase). **[HUMAN]** says when to push.
2. Fix the `docs/16`/`docs/17` references in `CLAUDE.md` and `HANDOFF.md`:
   either restore the two files from git history or repoint the references
   to their replacements.
3. **[DECISION] License.** Recommendation: **Apache-2.0**. It is permissive,
   has an explicit patent grant and is common for security tooling. AGPL-3.0
   is the alternative if you want hosted forks to stay open. Without a
   LICENSE file nobody can legally reuse the code.
4. Add `SECURITY.md` (a private disclosure route via GitHub private
   vulnerability reporting, which is free), `CONTRIBUTING.md`,
   `CHANGELOG.md` (Keep-a-Changelog format) and issue/PR templates.
5. Turn on Dependabot (pip, npm, GitHub Actions). It is free and adds one
   YAML file.

---

## 9D–9H. Finish Phase 9 (as specified in docs/33)

Nothing changes from docs/33 §9D–9H. Three points matter for shipping:

- **9D beaconing.** This is the main C2 signal, so CTU-13 and the Stratosphere
  captures (§3) become its *real* test set. Its Done-when should be measured
  there, not only on synthetic data.
- **9F audit keys.** **[HUMAN] security review before merge** (R-rule).
  Plan for the review time.
- **Exit Gate 9:** the FR-4.1 flip stays **unflipped** unless a later
  experiment beats the 9B finding. Record it as a known limitation, not a
  failure to hide.

---

## B. Benchmarks on real, free datasets (new phase; delivers 10.4)

### B.1 Datasets

All of these are free. "Gated" means a free registration form. Before
fetching any dataset, record its license, citation, URL and SHA-256 in
`docs/datasets.md` (R23: fresh directory, hashed, never in git).
**[DECISION]** approve each dataset before its first download, as HANDOFF
Phase 10 requires.

**Tier 1: no registration, directly on target**

| Dataset | What it scores in Spectra | Size (fetch subset) | Access | Status in repo |
|---|---|---|---|---|
| **CTU-13** scenarios 1, 2 + more (Stratosphere, CTU Prague) | `C2_BEACONING` recall; CTU "normal" flows give the benign FPR | 36–60 MB pcaps per scenario | direct HTTP | adapter + fetch exist |
| **Stratosphere CTU-Normal-\*** captures | Real *benign* traffic for FPR and for the overdue **9C real-traffic comparison** | 100 MB–1 GB each | direct HTTP | add catalog entries |
| **Stratosphere CTU-Malware-Capture-Botnet-\*** (modern TLS C2: Dridex, TrickBot, etc.) | TLS C2 recall; JA3/JA4/intel hits | varies | direct HTTP | add entries + reuse CTU adapter |
| **CSE-CIC-IDS2018** (CIC + AWS Open Data) | Precision/recall across RECONNAISSANCE, VOLUMETRIC, C2 (Bot), Infiltration; a second CIC-family benchmark | **use 2–3 days only** (the full set is hundreds of GB) | `aws s3 sync --no-sign-request s3://cse-cic-ids2018/…`, no account | new adapter (CSV layout matches CICIDS2017; verify the column names) |
| **HIKARI-2021** (Keio Univ., Zenodo) | Attacks *inside encrypted TLS* with benign background: the closest match to Spectra's thesis | CSV ~12 GB; pcaps per the GitHub instructions (verify) | Zenodo, no account | new adapter |
| **MAWI** samplepoint-F | Parser coverage on real backbone traffic; unscored anomaly rate | 1.3 GB/day | direct | exists |

**Tier 2: free but registration-gated, or weaker fit**

| Dataset | Use | Note |
|---|---|---|
| **CICIDS2017** + the **Engelen et al. corrected labels** (KU Leuven, `GintsEngelen/CNS2022_Code`) | The field's standard benchmark | Use the **corrected** labels and report both. The original labels have known errors (Engelen 2021; Liu et al. CNS 2022) |
| **CIRA-CIC-DoHBrw-2020** | DNS-over-HTTPS tunnelling counts as encrypted exfil → `DATA_EXFILTRATION_SUSPECTED` | gated (UNB form) |
| **ISCX VPN-nonVPN 2016** | Benign encrypted-app diversity; `UNUSUAL_ENDPOINT_BEHAVIOR` | gated; labels are apps, not attacks |
| **UNSW-NB15** | Third independent IDS benchmark (pcaps provided) | free from UNSW; aged (2015) |
| **CESNET-TLS-Year22 / CESNET-QUIC22** (Zenodo) | Benign TLS/QUIC drift at ISP scale (9E PSI drift) | **flow/packet-sequence features, not pcaps.** Needs a feature adapter, so stretch only. License not confirmed: check the Zenodo record |
| **malware-traffic-analysis.net** | Hand-picked real malware pcaps for qualitative case studies in the docs | password-zipped; follow the site's terms; never a precision source |

**Intel feeds** (free, already partly wired through `spectra intel`): abuse.ch
SSLBL (its JA3 list has been frozen since 2021), abuse.ch Feodo Tracker IP
blocklist, ThreatFox, ja4db.com fingerprints, and the Tranco top-1M list as a
*benign SNI* reference. Every feed stays "a signal, never a verdict".

**Own benign capture** **[HUMAN]**: 24–72 h of your own lab or home network.
Only networks you own, with everyone on them informed. This is the only way
to test the "baseline matching" limitation honestly.

**Disk:** keep about 150 GB free for Tier 1 subsets. Fetch per scenario with
`--only`; never fetch whole datasets.

### B.2 Protocol (fixed before the first run, written into each report)

1. **Train on benign only, from a separate time slice.** Example: CIC-2018
   train on a benign-only day, test on attack days; CTU train on CTU-Normal,
   test on botnet scenarios. Never test on time already trained on.
2. **Metrics:** use the docs/evaluation.md §6 metrics as they are, and add:
   - **95% bootstrap confidence intervals** (1000 resamples, fixed seed) on
     precision, recall and FPR.
   - **Operating points:** recall at benign FPR = 1% and 0.1%. These are the
     numbers an operator actually cares about.
   - **PR-AUC** next to ROC-AUC (ROC flatters imbalanced data).
3. **Baselines on the same pcaps** (all free; they keep our numbers honest):
   - **Suricata + ET Open rules**: the signature-IDS reference.
   - **Zeek + JA3/JA4 intel match**: the "fingerprint list" reference.
   - **A supervised RandomForest on Spectra's own 39 features**, trained with
     labels. This is an *upper bound*, not a competitor. It shows how much
     headroom the unsupervised detector leaves.
4. **Cross-dataset generalisation:** train on CTU-Normal and test on
   CIC-2018 (and the reverse). We expect this to be weak and must say so.
   This is the README's "baseline matching" warning, measured.
5. **Ablations:** with and without 9C augmentation, 9D beacon aggregation and
   JA4+ (9H). Each feature earns its place with a number.
6. **Performance** (same report, separate section):
   - Replay pcaps with `tcpreplay --topspeed` and at fixed rates (1k, 10k,
     50k pps) onto a veth pair. Record flows/s, packets/s, p50/p99
     flow-to-alert latency, CPU, RSS, and the drop counters from
     `/api/metrics`.
   - Run it on named machines: your laptop, plus an ARM box if one is
     available (e.g. a Raspberry Pi 5-class sensor). Publish the hardware
     specs with the numbers. The results become the "sizing guide" in the
     docs (§13.2): how much traffic a given box can handle.
7. **Adversarial:** run the 9B harness on each real dataset and report the
   evasion rate at the default budget. This is the FR-4.1 evidence, whatever
   the result.

### B.3 Tooling to build (minimal)

- Catalog entries in `fetch_datasets.py` for the new Tier-1 sources, plus
  two adapters (CIC-2018 CSV and HIKARI) in `eval/adapters.py`. Each adapter
  gets a fixture-based test, like the existing CTU/CICIDS ones.
- An `eval run --bootstrap N` option and an operating-point table in
  `eval/metrics.py`.
- `scripts/bench_baselines.sh`: runs Suricata and Zeek in their official
  Docker images over the same pcap and converts their output to the label
  join. Docker keeps them off the host.
- `scripts/bench_perf.sh`: a tcpreplay rig on a veth pair. It needs
  `CAP_NET_RAW`/sudo, which the **[HUMAN]** runs.
- **Nightly CI workflow:** fetch CTU-13 s1 (58 MB, cached with
  `actions/cache`), train, evaluate, and fail if recall or FPR regress past a
  stored threshold. A free GitHub runner fits this. The full benchmark stays
  a manual run.

### B.4 Deliverables

- `docs/evaluation-report.md`: one section per dataset, with the dataset
  hash, model hash, commit, date, command, CIs, baselines and caveats.
- `docs/evidence/<date>/bench/`: raw `eval_report.json` files plus the
  Suricata/Zeek outputs.
- A populated model card (`12_model_card.md` per HANDOFF Phase 10).
- The docs site's "Benchmarks" page **generated from those JSON files**,
  never hand-typed.

**Gate B:** at least 3 Tier-1 datasets evaluated; baselines included; every
published number traceable to a JSON file and a hash. If Spectra loses to
Suricata on some category, the report says so.

---

## 10. Security hardening (as in HANDOFF; additions for internet exposure)

All tools below are free. Save the raw outputs to `docs/evidence/<date>/` and
name the version and command for each (R-rules).

| Concern | Tool | Where |
|---|---|---|
| SAST | Semgrep CE (+ custom "payload outside `parse/`" rule), Bandit, **CodeQL** (free on public repos) | CI on every PR |
| Secrets | gitleaks (full history, before the repo goes public) | CI + one-off |
| SCA | pip-audit (already in CI), `npm audit`, OSV-Scanner, Dependabot | CI |
| SBOM / image | Syft (SBOM), Trivy or Grype (image CVEs) | release workflow |
| Supply chain | OpenSSF Scorecard action; cosign keyless signing of images (GitHub OIDC) | CI |
| DAST | Schemathesis against `/openapi.json`; OWASP ZAP baseline + API scan | **own loopback instance only** (R22–R24) |

**Additions for software that strangers will install.** We can't control
where users put it, so the defaults must be safe:

1. **Secure defaults.** It binds to `127.0.0.1` (already the default) and
   refuses to bind a non-loopback address over plain HTTP unless the user
   sets an explicit flag. The startup log warns when the UI is reachable
   without TLS.
2. **TLS path documented and tested.** Option (a) is a Caddy reverse-proxy
   example in `deploy/` with automatic certificates, HSTS and security
   headers (CSP, frame-ancestors). Option (b) is built-in
   `--tls-cert/--tls-key` for a single-box install. With TLS on,
   `SPECTRA_SESSION_COOKIE_SECURE=true`.
3. **Rate limiting** on login and write routes (small FastAPI middleware, no
   new dependency). Lockout with backoff (HANDOFF 10.6) must not enable
   username enumeration or lock out the only admin for good.
4. **TOTP for ADMIN** (HANDOFF 10.6).
5. **First-run safety.** The bootstrap admin password goes to a mode-0600
   file only, never to stdout or container logs (re-check under Docker), and
   the user must change it at first login.
6. **Capture privilege minimised.** Only the capture worker gets `NET_RAW`;
   the API/UI process runs unprivileged (§11.2). On bare-metal Linux, use
   `setcap cap_net_raw` instead of running as root.
7. **Threat-model refresh** for the "installed by a third party" boundary
   (unknown network, unknown exposure). Add ADRs for secure defaults and TLS.
8. **Vulnerability handling.** A `SECURITY.md` with a response-time target
   and supported-versions table; GitHub Security Advisories and CVE
   requests for real issues.
9. Run **gitleaks on the full history before the repo goes public.** The
   tree holds a git-ignored `backend/tee_attestation.key`; confirm no key
   material was ever committed. Release artifacts must never contain a
   generated key (add a test on the built wheel and image).
10. **[HUMAN]** security review and sign-off. This is the release gate; I
    cannot self-approve it.

---

## 11. Operational readiness (as in HANDOFF; concrete choices)

1. **Wheel:** `pip install spectra` → `spectra serve` serves the built
   frontend. Publish to TestPyPI first, then PyPI via **Trusted Publishing**
   (OIDC, no tokens stored). **[HUMAN]** creates the PyPI project; check name
   availability, since `spectra` is probably taken. **[DECISION]** fallback
   name, e.g. `spectra-ndr`.
2. **Docker:** multi-stage, non-root, read-only rootfs + tmpfs, pinned base
   digest, healthcheck. Use two compose profiles: `api` (no capabilities) and
   `capture` (`NET_RAW` + `NET_ADMIN`, host network). Build multi-arch
   (amd64 + arm64, for ARM servers and small sensors) and push to **GHCR**
   (free for public images).
3. **Platform support matrix** **[DECISION]**. The recommendation, tested in
   CI on every release:

   | Platform | Live capture | Offline PCAP analysis | CI |
   |---|---|---|---|
   | Linux x86_64 / arm64 (Docker or pip) | ✅ libpcap | ✅ | ubuntu runners (arm64 runners are free for public repos) |
   | macOS (pip) | ✅ BPF (needs sudo or ChmodBPF) | ✅ | macos runner, smoke test |
   | Windows (pip) | ⚠️ needs Npcap, installed by the user under its own license | ✅ | windows runner, smoke test |

   `start.ps1` shows Windows is used today. Npcap's license forbids
   redistribution, so Windows docs point users to its installer and we never
   bundle it.
4. **Upgrades.** Spectra already has numbered DB migrations. Add a CI job
   that installs the *previous* release, creates data, upgrades to the
   candidate, and runs the suite against the migrated DB. `spectra backup`
   runs automatically before migrating. Model artifacts carry a
   feature-schema version; an incompatible model is refused with a "retrain"
   message, not loaded silently.
5. **Offline / air-gapped install.** Many monitored networks have no
   internet. Ship a `docker save` tarball and a wheelhouse (`pip download`
   with hashes from `requirements.lock`) as release assets, with a docs page.
6. **Prometheus** text exposition on `/api/metrics?format=prom` + a
   **Grafana** dashboard JSON in `deploy/grafana/`. Both are OSS and
   optional for users.
7. **Backup/restore:** a `spectra backup` / `spectra restore` CLI
   (`sqlite3 .backup` + model artifacts + the audit-key escrow procedure).
   Run the restore drill in CI on a fixture DB and log the measured RTO/RPO.
8. **Operator runbook:** each step executed once on a local install, with
   output recorded. It ships in the docs as "Troubleshooting".

---

## 13. Release (new phase)

### 13.1 Docs site

- **MkDocs Material** on **GitHub Pages** (both free), versioned per release
  with `mike` so v1.0 docs stay readable after v1.1. Sources are the
  existing `docs/*.md` files. The nav covers:
  - Quickstart,
  - Install (Docker, pip, offline),
  - Sensor placement,
  - Sizing guide,
  - First baseline,
  - Architecture,
  - Benchmarks (generated),
  - Limitations (prominent, not buried),
  - Security hardening,
  - Upgrading,
  - Troubleshooting,
  - Datasets & attributions,
  - API (rendered from OpenAPI with Redoc).
- A dataset **attributions page** with every dataset's required citation.
  Most academic datasets ask for one.

### 13.2 User-facing guides the software needs (new docs)

1. **Sensor placement:** SPAN/mirror port vs network TAP vs host capture, and
   what each one sees. Covers asymmetric routing and VLAN tags.
2. **First baseline:** how long to record benign traffic before training,
   how to check that the baseline is clean, and when to retrain (drift
   alerts from 9E). The detector is unsupervised and trained per network,
   so this guide decides whether users get value or noise.
3. **Sizing guide:** packets/s and flows/s per CPU core, plus RAM and disk
   per day of retention. Generated from the §B.2 performance runs.
4. **Hardening checklist:** TLS, non-loopback binding, TOTP, retention
   settings, backups. Mirrors §10.
5. **Integrations:** reading alerts out through the API. A SIEM webhook is
   12A; it ships only if the owner authorises it.

### 13.3 Release process

- SemVer. Generate `CHANGELOG.md` from Conventional Commits, which the repo
  already uses.
- On tag: the GitHub Actions release workflow runs tests, then builds the
  wheel, image, SBOM and Trivy scan, signs with cosign, and publishes to
  PyPI, GHCR and GitHub Release notes. **Tags and pushes happen only on the
  owner's word** (CLAUDE.md).
- Release checklist in `docs/release-checklist.md`, ticked with command
  output for each release.
- **Pre-releases first:** `v1.0.0-rc.N` go to TestPyPI and a `:rc` image
  tag. Invite a few outside testers to install from the docs alone and file
  issues **[HUMAN]**. Promote to v1.0.0 only once the rc has had no
  release-blocking issue for one to two weeks.
- **Support policy** (in `SECURITY.md` and the docs): the latest minor
  release gets security fixes; the previous minor gets them for about 3
  months. No SemVer-breaking API or DB change without a major bump and a
  migration.
- **Verification for users:** document `cosign verify` for images and
  checksum or attestation checks for wheels (PyPI Trusted Publishing gives
  provenance attestations).

### 13.4 Legal and acceptable use

- A LICENSE file (S0), plus a `THIRD_PARTY_NOTICES` file generated from the
  SBOM (Python + npm dependency licenses). CI runs a license-allowlist
  check, so a GPL dependency can't slip into an Apache-2.0 project
  unnoticed.
- README + docs: "Deploy only on networks you own or are authorised to
  monitor." Note that passive capture laws and works-council rules vary by
  jurisdiction.
- A privacy statement for the software: no telemetry, no outbound calls,
  everything stays on the user's disk, metadata-only by design.
- Dataset licenses honoured (§B.1). No dataset bytes are redistributed in
  releases; the fetch scripts download from the original sources.
- Trademark check on the name "Spectra" before publishing packages
  **[DECISION]**. It is a common name; a distinct package or image name may
  be needed anyway (§11.1).

**Gate 13:** docs site live; v1.0.0 artifacts (wheel, multi-arch image,
offline bundle, SBOM) signed and published; installed on a fresh Linux,
macOS and Windows machine by following only the docs; upgrade from the last
rc passes; at least one outside tester's install reported.

---

## 14. Decisions and human actions (collected)

| # | Item | Type |
|---|---|---|
| 1 | When to push 9A–9C and how to merge them with PR #1 | [HUMAN] |
| 2 | License (recommend Apache-2.0) | [DECISION] |
| 3 | Approve each dataset before download (§B.1) | [DECISION] |
| 4 | Register for the CIC/UNB gated datasets | [HUMAN] |
| 5 | Record your own benign capture (optional, recommended) | [HUMAN] |
| 6 | Run the tcpreplay rig (needs sudo) | [HUMAN] |
| 7 | 9F crypto review; Phase 10 security sign-off | [HUMAN] |
| 8 | Retention defaults for the shipping profile | [DECISION] |
| 9 | PyPI/image name (trademark check) + PyPI project creation | [DECISION]/[HUMAN] |
| 10 | Supported platforms (recommended: Linux full; macOS/Windows best-effort) | [DECISION] |
| 11 | Recruit 3–5 outside rc testers | [HUMAN] |
| 12 | Make the GitHub repo public (after the gitleaks history scan) | [HUMAN] |
| 13 | Custom domain for docs (optional, ~$10/yr) | [DECISION] |

## 15. Risks

| Risk | Mitigation |
|---|---|
| Benchmarks show weak accuracy on real data | Publish anyway with baselines and limitations. Fix what the ablations point at. Never tune on the test split |
| Dataset label errors (CIC family) | Use the corrected labels where they exist; report both |
| Users expose the UI to the internet without TLS | Loopback default; a refusal or loud warning on plain-HTTP non-loopback; hardening checklist; TOTP + lockout |
| An upgrade breaks a user's DB or model | Previous-release → candidate upgrade job in CI; automatic backup before migrating; model schema versioning |
| Users get noise because their baseline is poor | "First baseline" guide; drift alerts (9E); honest limitations page |
| Capture doesn't work on a user's platform | Support matrix tested in CI; offline PCAP analysis works everywhere as a fallback |
| Disk or bandwidth for datasets | Subset fetches with `--only`; hash-verified resume already exists |
| Scope creep into SaaS | Out of scope unless the owner makes a new [DECISION] |
