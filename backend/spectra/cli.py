"""Spectra command line interface.

Examples:
    spectra train baseline.pcap --contamination 0.02
    spectra scan suspicious.pcap
    spectra serve --port 8000
    spectra status
"""

from __future__ import annotations

import argparse
import json
import sys


def cmd_train(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine(model_path=args.out)
    info = engine.train_from_pcap(args.pcap, contamination=args.contamination)
    print("model trained:")
    print(json.dumps(info, indent=2))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine(model_path=args.model)
    if not engine.detector.is_trained:
        print("no trained model found - run `spectra train <pcap>` first", file=sys.stderr)
        return 2

    events: list[dict] = []
    engine.subscribe(lambda e: events.append(e) if e["type"] == "detection" else None)
    engine.start("pcap", path=args.pcap)
    while engine.running:
        import time

        time.sleep(0.2)

    detections = [e["data"] for e in events]
    print(f"scanned {engine.status['packets']} packets -> "
          f"{engine.status['flows']} flows, {len(detections)} detections")
    for det in sorted(detections, key=lambda d: d["score"], reverse=True)[:args.top]:
        quic = f" quic={det['quic_version']}" if det.get("quic_version") else ""
        print(f"  [{det['score']:6.1f}] {det['proto']:3} {det['src']} -> {det['dst']} "
              f"sni={det['sni'] or '-'}{quic} reasons="
              f"{','.join(r['feature'] for r in det['reasons']) or '-'}")
    if args.json:
        print(json.dumps(detections, indent=2, default=str))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    import os

    from .demo import make_baseline_pcap, make_suspicious_pcap

    os.makedirs(args.out, exist_ok=True)
    baseline = os.path.join(args.out, "baseline.pcap")
    suspicious = os.path.join(args.out, "suspicious.pcap")
    make_baseline_pcap(baseline, n_flows=args.flows)
    make_suspicious_pcap(suspicious)
    print(f"wrote {baseline} (benign baseline, {args.flows} TLS + 2 QUIC flows)")
    print(f"wrote {suspicious} (mixed traffic with beacon flows)")
    if args.train:
        from .pipeline import SpectraEngine

        engine = SpectraEngine(model_path=args.model)
        info = engine.train_from_pcap(baseline, contamination=0.05)
        print(f"trained model -> {info['model_path']}")
    return 0


def cmd_pqc(args: argparse.Namespace) -> int:
    from .modules.pqc.scan import scan_pcap

    report = scan_pcap(args.pcap, sector=args.sector)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    s = report["summary"]
    print(f"PQC readiness scan: {report['pcap']}")
    print(f"  assessed flows : {report['assessed']}/{report['flows']}")
    print(f"  endpoints      : {s['endpoints']} "
          f"({s['vulnerable_endpoints']} vulnerable, "
          f"{s['quantum_ready_endpoints']} quantum-ready)")
    print(f"  HNDL findings  : {len(report['hndl'])}")
    if s["risk_distribution"]:
        dist = ", ".join(f"{k}={v}" for k, v in sorted(s["risk_distribution"].items()))
        print(f"  risk mix       : {dist}")

    print("\ntop endpoints by quantum exposure:")
    for ep in report["endpoints"][:args.top]:
        print(f"  [{ep['min_score']:5.1f}] {ep['endpoint']:<40} "
              f"sector={ep['sector']:<11} flows={ep['flows']:<4} "
              f"kx={','.join(ep['algorithms'][:2]) or '-'}")

    if report["hndl"]:
        print("\nHNDL suspects (harvest-now-decrypt-later):")
        for f in report["hndl"][:args.top]:
            print(f"  [{f['score']:3d} {f['level']:>6}] {f['endpoint']:<40} "
                  f"{f['bytes']:,}B {f['duration']:.1f}s sector={f['sector']}")

    print("\nroadmap:")
    for phase in report["roadmap"]["phases"]:
        print(f"  Phase {phase['phase']} ({phase['window']}):")
        for item in phase["items"]:
            print(f"    [{item['priority']}] {item['title']} "
                  f"(affected={item['affected']}, effort={item['effort']})")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine(model_path=args.model)
    print(json.dumps(engine.snapshot(), indent=2, default=str))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .modules.audit import CertificateError, PROFILES, verify_certificate
    from .pipeline import SpectraEngine

    engine = SpectraEngine()
    cmd = args.audit_cmd

    if cmd == "entries":
        import datetime as _dt

        page = engine.audit_entries(limit=args.limit, kind=args.kind)
        if args.json:
            print(json.dumps(page, indent=2, default=str))
            return 0
        print(f"audit log: {page['count']} entries "
              f"(signing key {page['signing_key'][:16]}...)")
        for e in page["items"]:
            leaves = f" leaves={len(e['leaves'])}" if e.get("leaves") else ""
            when = _dt.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S") \
                if e.get("ts") else "-"
            print(f"  #{e['seq']:<5} {when}  {e['kind']:<14} "
                  f"{e['entry_hash'][:16]}…{leaves}")
        return 0

    if cmd == "verify":
        report = engine.audit_verify()
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return 0 if report["ok"] else 1
        print(f"chain verification: {'OK' if report['ok'] else 'FAILED'} "
              f"({report['entries']} entries)")
        print(f"  head        : #{report['head']['seq']} {report['head']['entry_hash'][:24]}…")
        for err in report["errors"]:
            print(f"  ERROR #{err['seq']}: {err['reason']}")
        return 0 if report["ok"] else 1

    if cmd == "checkpoint":
        ck = engine.audit_checkpoint()
        if args.json:
            print(json.dumps(ck, indent=2, default=str))
            return 0
        print(f"checkpoint #{ck['seq']}: entries {ck['covered_from']}..{ck['covered_to']} "
              f"root {ck['root'][:24]}…")
        print(f"  signature: {ck['signature'][:32]}… (key {ck['pubkey'][:24]}…)")
        v = engine.audit_verify_checkpoint(seq=ck["seq"])
        print(f"  verify   : {'OK' if v['ok'] else 'FAILED'}")
        for c in v["checks"]:
            if not c["ok"]:
                print(f"    FAIL {c['name']}: {c['detail']}")
        return 0 if v["ok"] else 1

    if cmd == "proof":
        proof = engine.audit_proof(args.seq, args.leaf)
        print(json.dumps(proof, indent=2, default=str))
        ok = engine.audit.verify_inclusion(proof)
        print(f"inclusion verified: {ok}", file=sys.stderr)
        return 0 if ok else 1

    if cmd == "certify":
        try:
            bundle = engine.certify(profile=args.profile, since=args.since,
                                    until=args.until, min_flows=args.min_flows,
                                    disclose=args.disclose, bits=args.bits)
        except CertificateError as exc:
            print(f"certificate not issued: {exc}", file=sys.stderr)
            return 2
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=2)
            print(f"wrote {args.out}")
        if args.json:
            print(json.dumps(bundle, indent=2, default=str))
            return 0
        print(f"certificate issued: profile={bundle['profile']} "
              f"issuer={bundle['pubkey'][:16]}…")
        for claim in bundle["claims"]:
            detail = ""
            if claim["id"] == "detection_continuity":
                detail = (f" ({claim['evidence_count']} records, "
                          f"{len(claim['disclosed'])} disclosed, "
                          f"{claim['redacted']} redacted)")
            elif claim["id"] == "min_coverage":
                detail = f" (>= {claim['threshold']} flows, count hidden)"
            print(f"  [met] {claim['id']}: {claim['statement']}{detail}")
        res = verify_certificate(bundle, log=engine.audit, model_path=engine.model_path)
        print(f"verification: {'OK' if res['ok'] else 'FAILED'} "
              f"({len(res['checks'])} checks)")
        return 0 if res["ok"] else 1

    if cmd == "verify-cert":
        with open(args.file, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        res = verify_certificate(bundle, log=engine.audit, model_path=engine.model_path)
        if args.json:
            print(json.dumps(res, indent=2, default=str))
            return 0 if res["ok"] else 1
        print(f"certificate verification: {'OK' if res['ok'] else 'FAILED'}")
        for c in res["checks"]:
            mark = "ok  " if c["ok"] else "FAIL"
            print(f"  [{mark}] {c['name']}" + (f" - {c['detail']}" if c["detail"] else ""))
        return 0 if res["ok"] else 1

    if cmd == "profiles":
        for name, claims in PROFILES.items():
            print(f"  {name:<9} {', '.join(claims)}")
        return 0

    return 2  # pragma: no cover


def cmd_twin(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine()
    engine.hydrate_graph()   # one-shot CLI: rebuild the twin from persisted flows
    cmd = args.twin_cmd
    sim_kwargs = {
        "seed": getattr(args, "seed", 7),
        "rounds": getattr(args, "rounds", 12),
        "capability": getattr(args, "capability", 0.6),
        "monitoring": getattr(args, "monitoring", None),
        "controls": _controls_from_args(args),
    }

    if cmd == "topology":
        topo = engine.twin_topology(min_flows=args.min_flows)
        if args.json:
            print(json.dumps(topo, indent=2, default=str))
            return 0
        s = topo["summary"]
        print(f"twin topology: {s['nodes']} nodes / {s['assets']} assets / "
              f"{s['edges']} propagation edges / {s['zones']} zones")
        for z in topo["zones"]:
            print(f"  zone {z['id']:<12} assets={z['size']:<4} "
                  f"criticality={z['criticality']}")
        print(f"  mean criticality: {s['mean_criticality']}")
        return 0

    if cmd == "playbooks":
        lib = engine.twin_playbooks()
        for item in lib["items"]:
            print(f"  {item['name']:<20} {item['description']}")
            for a in item["actions"]:
                print(f"      round {a['round']}: {a['action']}"
                      f"{' -> ' + str(a['target']) if a.get('target') else ''}"
                      f"{' value=' + str(a['value']) if 'value' in a else ''}")
        return 0

    if cmd == "simulate":
        try:
            result = engine.twin_simulate(**sim_kwargs)
        except Exception as exc:  # noqa: BLE001 - report cleanly
            print(f"simulation failed: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0
        print(f"simulation: seed={result['seed']} rounds={result['rounds']} "
              f"capability={sim_kwargs['capability']}")
        print(f"  seeds        : {', '.join(result['initial'])}")
        print(f"  infected     : {result['total_infected']}/{result['assets']} "
              f"(blast {result['blast_ratio']:.0%}, peak {result['peak_infected']})")
        print(f"  sectors      : {', '.join(result['sectors_impacted']) or '-'}")
        print(f"  contained    : {result['contained']} "
              f"(last infection round {result['last_infection_round']})")
        for step in result["timeline"]:
            if step["new"] or step["detected"] or step["blocked"]:
                print(f"    round {step['round']:>2}: +{len(step['new'])} new, "
                      f"{len(step['detected'])} detected, {step['blocked']} blocked "
                      f"-> {step['infected']} active")
        return 0

    if cmd == "playbook":
        try:
            if args.all:
                report = engine.twin_evaluate(**sim_kwargs)
                if args.json:
                    print(json.dumps(report, indent=2, default=str))
                    return 0
                print(f"playbook rehearsal ranking (seed={report['seed']}):")
                for p in report["playbooks"]:
                    mark = {"pass": "PASS", "noop": "NOOP",
                            "fail": "FAIL"}.get(p["verdict"]["state"], "ERR ")
                    print(f"  #{p['rank']} [{mark}] {p['playbook']:<20} "
                          f"reduction={p.get('reduction', 0):.0%} "
                          f"efficiency={p.get('efficiency', 0):.0%}")
                    for reason in p["verdict"]["reasons"]:
                        print(f"        {reason}")
                print(f"  best: {report['best']}")
                return 0
            report = engine.twin_validate(name=args.name, **sim_kwargs)
        except Exception as exc:  # noqa: BLE001
            print(f"playbook rehearsal failed: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return 0 if report["verdict"]["pass"] else 1
        v = report["verdict"]
        print(f"playbook '{report['playbook']}': {v['state'].upper()}")
        print(f"  baseline : {report['baseline']['total_infected']} infected, "
              f"sectors {report['sectors_before']}")
        print(f"  after    : {report['after']['total_infected']} infected, "
              f"sectors {report['sectors_after']}")
        print(f"  reduction: {report['reduction']:.0%} of {report['attainable']:.0%} "
              f"attainable (efficiency {report['efficiency']:.0%})")
        for reason in v["reasons"]:
            print(f"    -> {reason}")
        return 0 if v["pass"] else 1

    if cmd == "shadow":
        result = engine.shadow(pcap=args.pcap, contamination=args.contamination,
                               threshold=args.threshold)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0 if result.get("available") else 2
        if not result.get("available"):
            print(f"shadow mode unavailable: {result.get('reason')}", file=sys.stderr)
            return 2
        c = result["comparison"]
        print(f"shadow mode ({result['source']}): {result['window']} flows")
        print(f"  reference flags : {c['reference_flags']}")
        print(f"  legacy flags    : {c['baseline_flags']} "
              f"(agreement {c['baseline_agreement']:.0%}, "
              f"missed {c['missed_by_baseline']})")
        m = c["baseline_vs_reference"]
        print(f"  legacy vs ref   : precision {m['precision']:.0%} "
              f"recall {m['recall']:.0%} f1 {m['f1']:.0%}")
        if "candidate_vs_reference" in c:
            cm = c["candidate_vs_reference"]
            print(f"  candidate vs ref: precision {cm['precision']:.0%} "
                  f"recall {cm['recall']:.0%} f1 {cm['f1']:.0%} "
                  f"(f1 lift {result['improvement']['f1_lift_vs_baseline']:+.0%})")
        print(f"  verdict: {result['verdict']}")
        return 0

    return 2  # pragma: no cover


def cmd_bio(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine()
    cmd = args.bio_cmd

    if cmd == "status":
        report = engine.bio_report()
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return 0 if report.get("available") else 2
        if not report.get("available"):
            print("bio layer unavailable: retrain the model to fit the self model",
                  file=sys.stderr)
            return 2
        s = report["swarm"]
        print(f"bio layer: assessed {report['assessed']} flow(s), "
              f"{report['memory_cells']} memory cell(s)")
        print(f"  self model : trained ({report['self_model']['n_features']} features)")
        thr = report["snn"]["threshold"]
        print(f"  snn        : "
              f"{'trained, threshold=' + str(round(thr, 4)) if report['snn']['trained'] else 'untrained'}, "
              f"flag at >= {report['snn']['threshold_pct']}%")
        print(f"  swarm      : quorum {s['quorum']} over {s['min_agents']}+ agents")
        for agent, weight in s["weights"].items():
            print(f"      {agent:<9} pheromone {weight:.3f}")
        hist = report["response_histogram"]
        print("  responses  : " + ", ".join(f"{k}={v}" for k, v in hist.items()))
        print(f"  context    : drift={report['drift_level']} "
              f"evasion={report['evasion_active']} "
              f"timing_scale={report['timing_scale']}")
        return 0

    if cmd == "assess":
        from .features.extractor import flows_to_matrix
        from .modules.bio import RESPONSES
        from .tools import collect_flows

        if not engine.bio.available:
            print("bio layer unavailable: retrain the model first", file=sys.stderr)
            return 2
        flows = collect_flows(args.pcap)
        if not flows:
            print(f"no flows in {args.pcap}", file=sys.stderr)
            return 2
        X = flows_to_matrix(flows)
        results = []
        for i, (flow, feats) in enumerate(zip(flows, X)):
            score = None
            anomaly = False
            if engine.detector.is_trained:
                score = float(engine.detector.score(feats)[0])
                anomaly = bool(engine.detector.predict(feats)[0])
            out = engine.bio.assess(feats, score=score, anomaly=anomaly,
                                    timing_scale=engine.edge.timing_scale())
            results.append((i, flow, score, out))
        if args.json:
            print(json.dumps([{"flow": i, **out} for i, _, _, out in results],
                             indent=2, default=str))
            return 0
        counts: dict[int, int] = {}
        for _, _, _, out in results:
            counts[out["level"]] = counts.get(out["level"], 0) + 1
        print(f"bio assessment of {len(results)} flow(s) from {args.pcap}")
        print("  responses : " + ", ".join(
            f"{RESPONSES[i]}={counts.get(i, 0)}" for i in range(len(RESPONSES))))
        worst = sorted(results,
                       key=lambda r: (-r[3]["level"],
                                      -r[3]["immune"]["affinity"]))[:3]
        for i, flow, _, out in worst:
            rec = flow.record()
            imm = out["immune"]
            print(f"  #{i} {rec['src']} -> {rec['dst']}: {out['response']} "
                  f"(level {out['level']}, affinity {imm['affinity']}, "
                  f"danger {imm['danger_total']}, snn {out['snn']['score']}, "
                  f"swarm {out['swarm']['flag']})")
        return 0

    return 2  # pragma: no cover


def cmd_tee(args: argparse.Namespace) -> int:
    from .pipeline import SpectraEngine

    engine = SpectraEngine()
    cmd = args.tee_cmd

    if cmd == "attest":
        quote = engine.tee_attest(nonce=args.nonce)
        if args.json:
            print(json.dumps(quote, indent=2, default=str))
            return 0
        print("TEE quote (attestation-as-a-service):")
        print(f"  measurement: {quote['measurement']}...")
        print(f"  nonce      : {quote['nonce']}")
        print(f"  issued     : {quote['ts']}")
        print(f"  pubkey     : {quote['pubkey'][:32]}...")
        print(f"  signature  : {quote['signature'][:64]}...")
        return 0

    if cmd == "verify":
        try:
            with open(args.file, "rb") as fh:
                raw = fh.read()
            # PowerShell 5.1 '>' writes UTF-16LE (FF FE BOM); utf-8-sig the rest
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                text = raw.decode("utf-16")
            else:
                text = raw.decode("utf-8-sig")
            quote = json.loads(text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"cannot read quote: {exc}", file=sys.stderr)
            return 2
        res = engine.tee_verify(quote, measurement=args.measurement,
                                max_age=args.max_age, nonce=args.nonce)
        if args.json:
            print(json.dumps(res, indent=2, default=str))
            return 0 if res["ok"] else 1
        print(f"attestation {'VERIFIED' if res['ok'] else 'REJECTED'}")
        for check in res["checks"]:
            print(f"  [{'ok' if check['ok'] else 'FAIL'}] {check['name']}: "
                  f"{check['detail']}")
        return 0 if res["ok"] else 1

    if cmd == "infer":
        from .features.extractor import flows_to_matrix
        from .tools import collect_flows

        if not engine.detector.is_trained:
            print("no trained model - run `spectra train <pcap>` first",
                  file=sys.stderr)
            return 2
        flows = collect_flows(args.pcap)
        if not flows:
            print(f"no flows in {args.pcap}", file=sys.stderr)
            return 2
        X = flows_to_matrix(flows)
        scores = engine.detector.score(X)
        pick = max(range(len(X)), key=lambda i: float(scores[i]))
        result = engine.tee_infer(X[pick].tolist())
        if args.json:
            print(json.dumps(result, indent=2, default=str))
            return 0
        rec = flows[pick].record()
        print(f"sealed inference on {rec['src']} -> {rec['dst']}")
        print(f"  score    : {result['score']} (flagged {result['flagged']})")
        print(f"  payload  : {result['claims']['payload_bytes']} bytes enter the enclave")
        print(f"  model    : {result['claims']['model_measurement']}")
        print(f"  receipt  : {result['receipt']['signature']}...")
        return 0

    if cmd == "federate":
        import numpy as np

        from .features.extractor import flows_to_matrix
        from .tools import collect_flows

        deltas = None
        if args.pcap:
            flows = collect_flows(args.pcap)
            if not flows:
                print(f"no flows in {args.pcap}", file=sys.stderr)
                return 2
            X = flows_to_matrix(flows)
            step = max(1, len(X) // 3)
            groups = [X[i * step:(i + 1) * step] for i in range(3)]
            deltas = [np.asarray(g).mean(axis=0).tolist()
                      for g in groups if len(g)]
        try:
            report = engine.tee_federate(deltas=deltas,
                                         shareholders=args.shareholders,
                                         seed=args.seed)
        except Exception as exc:  # noqa: BLE001 - report cleanly
            print(f"federated round failed: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, indent=2, default=str))
            return 0
        print(f"federated round: {report['parties']} parties x "
              f"{report['shareholders']} shareholders, dim {report['dim']}")
        print(f"  exact recombination : {report['exact']}")
        head = [round(v, 6) for v in report["aggregate"][:4]]
        print(f"  aggregate (first 4) : {head}")
        c = report["claims"]
        print(f"  raw data egress     : {c['raw_data_egress']} "
              f"(coordinator learns: {c['learned_by_coordinator']})")
        print(f"  caveat              : {c['caveat']}")
        return 0

    return 2  # pragma: no cover


def cmd_edge(args: argparse.Namespace) -> int:
    from .modules.edge import EdgeError, SLICES, apply_slice_policy, classify_slice
    from .pipeline import SpectraEngine

    engine = SpectraEngine()
    cmd = args.edge_cmd

    if cmd == "report":
        rep = engine.edge_report()
        if args.json:
            print(json.dumps(rep, indent=2, default=str))
            return 0
        link = rep["link"]
        micro = rep["micro"]
        print(f"edge runtime: link={link['link']} (rtt {link['rtt_ms']:.0f}ms, "
              f"timing x{link['timing_scale']})")
        state = "trained" if micro["trained"] else "untrained"
        print(f"  micro detector: {state}, {micro['n_features']} features, "
              f"budget {micro['budget_ms']}ms")
        if micro.get("latency"):
            lat = micro["latency"]
            print(f"    latency p50={lat['p50_ms']}ms p95={lat['p95_ms']}ms "
                  f"within budget={lat['within_budget']}")
        print("  slices: " + ", ".join(
            f"{k}={rep['slice_counts'].get(k, 0)}" for k in rep["slices"]))
        for sid, pol in rep["slices"].items():
            print(f"    {sid:<8} {pol['label']} ({pol['policy']})")
        if rep["deployments"]:
            print("  deployments:")
            for d in rep["deployments"]:
                print(f"    {d['node']} -> {d['slice']} via {d['link']} "
                      f"(digest {(d['digest'] or '')[:16]})")
        return 0

    if cmd == "link":
        try:
            rep = engine.edge_set_link(args.name)
        except EdgeError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        engine.edge_save()
        if args.json:
            print(json.dumps(rep, indent=2, default=str))
            return 0
        link = rep["link"]
        print(f"link profile set: {link['link']} ({link['label']})")
        print(f"  rtt {link['rtt_ms']:.0f}ms, jitter {link['jitter_ms']:.0f}ms, "
              f"timing scale x{link['timing_scale']} (persisted)")
        return 0

    if cmd == "slice":
        record = {
            "sni": args.sni,
            "bytes": args.bytes,
            "packets": args.packets,
            "duration": args.duration,
            "tls_version": args.tls,
        }
        slice_id = classify_slice(record)
        adjusted, note = apply_slice_policy(args.level, slice_id)
        if args.json:
            print(json.dumps({
                "slice": slice_id,
                "policy": SLICES[slice_id],
                "level": args.level,
                "adjusted_level": adjusted,
                "note": note,
            }, indent=2, default=str))
            return 0
        pol = SLICES[slice_id]
        print(f"slice: {slice_id} ({pol['label']})")
        print(f"  policy : {pol['policy']}")
        print(f"  level {args.level} -> {adjusted} ({note})")
        return 0

    if cmd == "deploy":
        try:
            profile = engine.edge_deploy(args.node, args.slice)
        except EdgeError as exc:
            print(f"deploy failed: {exc}", file=sys.stderr)
            return 2
        engine.edge_save()
        if args.json:
            print(json.dumps(profile, indent=2, default=str))
            return 0
        print(f"deployed micro-detector to {profile['node']} "
              f"(slice {profile['slice']}, link {profile['link']})")
        print(f"  features: {len(profile['features'])}, "
              f"flag at >= {profile['threshold_pct']}%")
        print(f"  digest  : {profile['digest']}...")
        return 0

    return 2  # pragma: no cover


def _controls_from_args(args: argparse.Namespace) -> dict:
    controls: dict = {}
    if getattr(args, "segment_zones", False):
        controls["segment_zones"] = True
    if getattr(args, "egress_filter", False):
        controls["egress_filter"] = True
    if getattr(args, "patch_hosts", 0):
        controls["patch_hosts"] = args.patch_hosts
    if getattr(args, "control_monitoring", None) is not None:
        controls["monitoring"] = args.control_monitoring
    return controls


def _add_sim_args(p: argparse.ArgumentParser) -> None:
    """Shared simulation flags for the twin subcommands."""
    p.add_argument("--seed", type=int, default=7, help="simulation seed")
    p.add_argument("--rounds", type=int, default=12, help="propagation rounds")
    p.add_argument("--capability", type=float, default=0.6,
                   help="attacker capability 0..1")
    p.add_argument("--monitoring", type=float, default=None,
                   help="standing detection probability per round 0..1")
    p.add_argument("--segment-zones", action="store_true",
                   help="control: segment cross-zone traffic")
    p.add_argument("--egress-filter", action="store_true",
                   help="control: filter external egress")
    p.add_argument("--patch-hosts", type=int, default=0,
                   help="control: patch the N most critical assets")
    p.add_argument("--control-monitoring", type=float, default=None,
                   help="control: standing monitoring probability")
    p.add_argument("--json", action="store_true", help="dump full JSON")


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("spectra.api.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_adversarial(args: argparse.Namespace) -> int:
    from .features.extractor import flows_to_matrix
    from .modules.adv import attack_batch
    from .pipeline import SpectraEngine
    from .tools import collect_flows

    engine = SpectraEngine(model_path=args.model)
    if not engine.detector.is_trained:
        print("no trained model found - run `spectra train <pcap>` first",
              file=sys.stderr)
        return 2

    flows = collect_flows(args.pcap)
    if not flows:
        print(f"no flows in {args.pcap}", file=sys.stderr)
        return 2
    X = flows_to_matrix(flows)

    rob = attack_batch(engine.detector, X)
    drift = engine.detector.psi(X)

    if args.json:
        print(json.dumps({"robustness": rob, "drift": drift}, indent=2,
                         default=str))
        return 0

    print(f"adversarial resilience report: {args.pcap}")
    print(f"  flows evaluated : {rob['evaluated']}")
    print(f"  flagged         : {rob['flagged']}")
    print(f"  evaded          : {rob['evaded']} "
          f"(rate {rob['evasion_rate']:.0%}) -> {rob['level']}")
    if rob["median_l2"] is not None:
        print(f"  median perturb. : L2={rob['median_l2']} "
              f"relative L1={rob['median_relative_l1']}")
    if rob["most_targeted_features"]:
        feats = ", ".join(f"{n}x{c}" for n, c in rob["most_targeted_features"][:5])
        print(f"  attacked feats  : {feats}")

    if drift.get("available"):
        print(f"  drift (PSI)     : {drift['psi']} -> {drift['level']} "
              f"(window {drift['n']})")
        for row in drift["features"][:5]:
            if not row.get("constant"):
                print(f"      {row['feature']:<24} psi={row['psi']}")
    else:
        print(f"  drift (PSI)     : unavailable ({drift.get('reason')})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spectra", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("train", help="train the detector on a benign baseline PCAP")
    p.add_argument("pcap", help="path to baseline (benign) PCAP")
    p.add_argument("--contamination", type=float, default=0.02,
                   help="expected anomaly fraction of the baseline (default 0.02)")
    p.add_argument("--out", default=None, help="output model path")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("scan", help="run detection over a PCAP")
    p.add_argument("pcap", help="path to PCAP to scan")
    p.add_argument("--model", default=None, help="model path")
    p.add_argument("--top", type=int, default=20, help="max detections to print")
    p.add_argument("--json", action="store_true", help="dump detections as JSON")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("demo", help="generate demo PCAPs (benign baseline + suspicious mix)")
    p.add_argument("--out", default="data/demo", help="output directory")
    p.add_argument("--flows", type=int, default=40, help="benign flows in the baseline")
    p.add_argument("--train", action="store_true", help="train the model on the baseline")
    p.add_argument("--model", default=None, help="model path (with --train)")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("pqc", help="Module 1: post-quantum readiness report for a PCAP")
    p.add_argument("pcap", help="path to PCAP to analyse")
    p.add_argument("--sector", default=None,
                   help="restrict report to a sector (fintech|healthcare|smart_city)")
    p.add_argument("--top", type=int, default=15, help="max rows per table")
    p.add_argument("--json", action="store_true", help="dump full report as JSON")
    p.set_defaults(func=cmd_pqc)

    p = sub.add_parser("adversarial",
                       help="Module 3: evasion robustness + drift report for a PCAP")
    p.add_argument("pcap", help="path to PCAP to attack/evaluate")
    p.add_argument("--model", default=None, help="model path")
    p.add_argument("--json", action="store_true", help="dump full report as JSON")
    p.set_defaults(func=cmd_adversarial)

    # -- Module 5: ZK audit trail -------------------------------------------

    p = sub.add_parser("audit",
                       help="Module 5: zero-knowledge audit trail + certificates")
    asub = p.add_subparsers(dest="audit_cmd", required=True)

    q = asub.add_parser("entries", help="list hash-chained audit entries")
    q.add_argument("--limit", type=int, default=20, help="max entries to print")
    q.add_argument("--kind", default=None, help="filter by entry kind")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("verify", help="verify sequence/prev-links/entry hashes")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("checkpoint",
                        help="Merkle-root + Schnorr-sign entries since last checkpoint")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("proof", help="Merkle inclusion proof for one committed leaf")
    q.add_argument("--seq", type=int, required=True, help="audit entry sequence")
    q.add_argument("--leaf", type=int, required=True, help="leaf index in that entry")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("certify", help="issue a signed compliance certificate")
    q.add_argument("--profile", default="hipaa", choices=["hipaa", "pci_dss", "gdpr"])
    q.add_argument("--since", type=float, default=None, help="window start (epoch)")
    q.add_argument("--until", type=float, default=None, help="window end (epoch)")
    q.add_argument("--min-flows", type=int, default=1, help="coverage threshold to prove")
    q.add_argument("--disclose", type=int, default=3, help="sample records to disclose")
    q.add_argument("--bits", type=int, default=32, help="range-proof bit width")
    q.add_argument("--out", default=None, help="write the certificate JSON here")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("verify-cert", help="verify a certificate bundle file")
    q.add_argument("file", help="path to certificate JSON")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_audit)

    q = asub.add_parser("profiles", help="list claim sets per compliance profile")
    q.set_defaults(func=cmd_audit)

    # -- Module 4: digital twin ---------------------------------------------

    p = sub.add_parser("twin",
                       help="Module 4: digital twin simulation + playbook rehearsal")
    tsub = p.add_subparsers(dest="twin_cmd", required=True)

    q = tsub.add_parser("topology", help="show the replica built from observed traffic")
    q.add_argument("--min-flows", type=int, default=1)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_twin)

    q = tsub.add_parser("playbooks", help="list the built-in IR playbook library")
    q.set_defaults(func=cmd_twin)

    q = tsub.add_parser("simulate", help="run one deterministic attack simulation")
    _add_sim_args(q)
    q.set_defaults(func=cmd_twin)

    q = tsub.add_parser("playbook",
                        help="rehearse one playbook (or --all to rank the library)")
    q.add_argument("--name", default="beacon_containment",
                   help="library playbook name or 'auto' (from live detections)")
    q.add_argument("--all", action="store_true", help="rank every library playbook")
    _add_sim_args(q)
    q.set_defaults(func=cmd_twin)

    q = tsub.add_parser("shadow", help="shadow mode: lift over a legacy z-score rule")
    q.add_argument("--pcap", default=None, help="PCAP to evaluate (default: live window)")
    q.add_argument("--contamination", type=float, default=0.05)
    q.add_argument("--threshold", type=float, default=3.5)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_twin)

    # -- Module 6: bio-inspired detection -----------------------------------

    p = sub.add_parser("bio",
                       help="Module 6: immune danger + SNN timing + swarm consensus")
    bsub = p.add_subparsers(dest="bio_cmd", required=True)

    q = bsub.add_parser("status", help="self model, SNN, swarm pheromones, memory")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_bio)

    q = bsub.add_parser("assess", help="assess every flow in a PCAP")
    q.add_argument("pcap", help="path to PCAP")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_bio)

    # -- Module 2: confidential computing ------------------------------------

    p = sub.add_parser("tee",
                       help="Module 2: attestation, sealed inference, federated rounds")
    tesub = p.add_subparsers(dest="tee_cmd", required=True)

    q = tesub.add_parser("attest", help="signed quote of the model measurement")
    q.add_argument("--nonce", default=None, help="challenge nonce to bind")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_tee)

    q = tesub.add_parser("verify", help="verify a quote JSON file")
    q.add_argument("file", help="path to quote JSON")
    q.add_argument("--measurement", default=None,
                   help="expected measurement (default: current model artifact)")
    q.add_argument("--max-age", type=float, default=600.0, help="max quote age (s)")
    q.add_argument("--nonce", default=None, help="challenge nonce to match")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_tee)

    q = tesub.add_parser("infer",
                         help="sealed inference on the worst flow of a PCAP")
    q.add_argument("pcap", help="path to PCAP")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_tee)

    q = tesub.add_parser("federate", help="additive secret-sharing round")
    q.add_argument("--pcap", default=None,
                   help="build the 3 party deltas from this PCAP")
    q.add_argument("--shareholders", type=int, default=3)
    q.add_argument("--seed", type=int, default=7)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_tee)

    # -- Module 8: 5G/6G edge -----------------------------------------------

    p = sub.add_parser("edge",
                       help="Module 8: slices, MEC micro-detector, NTN links")
    esub = p.add_subparsers(dest="edge_cmd", required=True)

    q = esub.add_parser("report", help="slices, micro-detector, link profiles")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_edge)

    q = esub.add_parser("link", help="set the NTN backhaul profile (persisted)")
    q.add_argument("name", help="terrestrial|uav|leo_satellite|geostationary")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_edge)

    q = esub.add_parser("slice", help="classify fields onto a 5G slice")
    q.add_argument("--sni", default=None, help="SNI / hostname")
    q.add_argument("--bytes", type=float, default=0.0, help="flow bytes")
    q.add_argument("--packets", type=float, default=0.0, help="packet count")
    q.add_argument("--duration", type=float, default=1.0, help="seconds")
    q.add_argument("--tls", default=None, help="tls_version if present")
    q.add_argument("--level", type=int, default=2, help="response level to preview")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_edge)

    q = esub.add_parser("deploy", help="deploy the micro-detector on a MEC node")
    q.add_argument("node", help="edge node id (e.g. mec-01)")
    q.add_argument("--slice", default="default",
                   choices=["urllc", "embb", "mmtc", "default"])
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_edge)

    p = sub.add_parser("status", help="print engine snapshot (model info, buffers)")
    p.add_argument("--model", default=None, help="model path")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("serve", help="run the API + dashboard backend")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--reload", action="store_true")
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    from .config import setup_logging

    args = build_parser().parse_args(argv)
    setup_logging()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI reports errors cleanly
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
