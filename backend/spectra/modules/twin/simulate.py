"""Module 4: attack-propagation simulation over the twin.

Design notes:

* **Deterministic, seedable, paired.** Every potential infection decision
  draws its uniform value from ``sha256(seed | round | from | to)`` instead of
  a sequential RNG stream. Same inputs -> same result, and - crucially - a
  baseline run and a playbooks run consume *the same* per-edge draws, so any
  difference in outcome is attributable to the containment actions rather
  than RNG luck (paired comparison, like an A/B test).
* **Metadata-only.** Propagation follows observed flows; no payload, no
  invented links.
* **Controls vs actions.** Controls are standing posture (segmentation,
  patching, monitoring); actions are timed playbook interventions applied at
  a specific round.
"""

from __future__ import annotations

import hashlib

SEGMENT_FACTOR = 0.15   # cross-zone spread multiplier when segmented
EGRESS_FACTOR = 0.35    # spread multiplier towards/through external zone

KNOWN_CONTROLS = ("segment_zones", "patch_hosts", "egress_filter", "monitoring")
KNOWN_ACTIONS = ("isolate_host", "block_ip", "block_domain", "segment_zone",
                 "patch", "monitor")


class SimulationError(ValueError):
    pass


def _draw(seed: int, round_no: int, src: str, dst: str, tag: str = "edge") -> float:
    """Deterministic uniform in [0, 1) for one (round, edge) decision."""
    key = f"spectra/twin/{seed}|{tag}|{round_no}|{src}|{dst}".encode()
    return int.from_bytes(hashlib.sha256(key).digest(), "big") / float(1 << 256)


def resolve_initial(topology: dict, initial: list[str] | None,
                    count: int = 2) -> list[str]:
    """Explicit seed nodes, else the most suspicious assets (detections first)."""
    assets = set(topology["assets"])

    def _resolve(name: str) -> str | None:
        # accept full ids ("host:10.0.0.5") and bare labels ("10.0.0.5")
        for candidate in (name, f"host:{name}", f"ip:{name}"):
            if candidate in assets:
                return candidate
        return None

    if initial:
        chosen = sorted({r for r in (_resolve(n) for n in initial) if r})
        if not chosen:
            raise SimulationError(
                f"no requested seed node is an asset of this twin: {initial}"
            )
        return chosen
    ranked = sorted(
        (n for n in topology["nodes"] if n["asset"]),
        key=lambda n: (-n["detections"], -n["criticality"], n["id"]),
    )
    return [n["id"] for n in ranked[: max(1, count)]]


def _resolved_controls(topology: dict, controls: dict | None,
                       initial: list[str]) -> dict:
    controls = dict(controls or {})
    unknown = set(controls) - set(KNOWN_CONTROLS)
    if unknown:
        raise SimulationError(
            f"unknown control(s) {sorted(unknown)}; known: {list(KNOWN_CONTROLS)}"
        )
    out = {
        "segment_zones": bool(controls.get("segment_zones", False)),
        "egress_filter": bool(controls.get("egress_filter", False)),
        "monitoring": float(controls.get("monitoring", 0.0)),
        "immune": set(),
    }
    patch = controls.get("patch_hosts", 0)
    if patch is True:
        patch = 3
    patch = int(patch or 0)
    if patch > 0:
        ranked = sorted(
            (n for n in topology["nodes"] if n["asset"] and n["id"] not in initial),
            key=lambda n: (-n["criticality"], n["id"]),
        )
        out["immune"] = {n["id"] for n in ranked[:patch]}
    if not 0.0 <= out["monitoring"] <= 1.0:
        raise SimulationError("monitoring must be in [0, 1]")
    return out


def _adjacency(topology: dict) -> dict[str, list[tuple[str, float, bool, bool]]]:
    adj: dict[str, list[tuple[str, float, bool, bool]]] = {}
    for e in topology["asset_edges"]:
        adj.setdefault(e["source"], []).append(
            (e["target"], e["normalized"], bool(e["cross_zone"]), bool(e["to_external"]))
        )
        # propagation is undirected: connections run both ways
        adj.setdefault(e["target"], []).append(
            (e["source"], e["normalized"], bool(e["cross_zone"]), bool(e["to_external"]))
        )
    for nbrs in adj.values():
        nbrs.sort()
    return adj


def simulate(topology: dict, initial: list[str] | None = None, seed: int = 7,
             rounds: int = 12, capability: float = 0.6,
             monitoring: float | None = None, controls: dict | None = None,
             actions: list[dict] | None = None, seed_count: int = 2) -> dict:
    """Run one deterministic propagation simulation.

    ``actions`` = [{"round": 1, "action": "isolate_host", "target": "..."}]
    """
    if rounds < 1 or rounds > 256:
        raise SimulationError("rounds must be in [1, 256]")
    if not 0.0 <= capability <= 1.0:
        raise SimulationError("capability must be in [0, 1]")
    if not topology.get("assets"):
        raise SimulationError("twin has no assets - run a capture first")

    seeds = resolve_initial(topology, initial, count=seed_count)
    ctl = _resolved_controls(topology, controls, seeds)
    if monitoring is not None:
        ctl["monitoring"] = float(monitoring)
        if not 0.0 <= ctl["monitoring"] <= 1.0:
            raise SimulationError("monitoring must be in [0, 1]")

    # action schedule: round -> list of actions (sorted, validated)
    schedule: dict[int, list[dict]] = {}
    for act in actions or []:
        unknown = set(act) - {"round", "action", "target", "value"}
        if unknown:
            raise SimulationError(f"unknown action field(s): {sorted(unknown)}")
        if act.get("action") not in KNOWN_ACTIONS:
            raise SimulationError(
                f"unknown action {act.get('action')!r}; known: {list(KNOWN_ACTIONS)}"
            )
        when = int(act.get("round", 1))
        if when < 0 or when > rounds:
            raise SimulationError(f"action round {when} outside [0, {rounds}]")
        schedule.setdefault(when, []).append(act)

    adj = _adjacency(topology)
    zone = {n["id"]: n["zone"] for n in topology["nodes"]}
    crit = {n["id"]: n["criticality"] for n in topology["nodes"]}
    assets = set(topology["assets"])
    by_domain = topology.get("by_domain", {})

    infected: set[str] = set(seeds)
    ever: set[str] = set(seeds)
    timeline: list[dict] = []
    blocked_total = 0
    last_infection_round: int | None = None
    peak, peak_round = len(seeds), 0
    zone_factor = SEGMENT_FACTOR if ctl["segment_zones"] else 1.0
    egress_factor = EGRESS_FACTOR if ctl["egress_filter"] else 1.0
    monitoring_p = ctl["monitoring"]
    immune: set[str] = set(ctl["immune"])
    quarantined: set[str] = set()
    action_log: list[dict] = []

    for r in range(0, rounds):
        # -- apply scheduled interventions at the start of the round --------
        for act in schedule.get(r, []):
            kind, target = act["action"], act.get("target")
            applied = 0
            if kind in ("isolate_host", "block_ip"):
                if target in assets:
                    quarantined.add(target)
                    applied = 1
            elif kind == "block_domain":
                dom = target if target in by_domain else f"domain:{target}"
                for ip_id in by_domain.get(dom, []):
                    quarantined.add(ip_id)
                    applied += 1
            elif kind == "segment_zone":
                zone_factor = float(act.get("value", SEGMENT_FACTOR))
            elif kind == "patch":
                k = int(act.get("value", 3))
                ranked = sorted(
                    (n for n in topology["nodes"]
                     if n["asset"] and n["id"] not in ever),
                    key=lambda n: (-n["criticality"], n["id"]),
                )
                before = len(immune)
                immune |= {n["id"] for n in ranked[:k]}
                applied = len(immune) - before
            elif kind == "monitor":
                monitoring_p = float(act.get("value", 0.5))
            action_log.append({"round": r, "action": kind,
                               "target": target, "applied": applied})

        # -- propagate ------------------------------------------------------
        new_infected: list[str] = []
        blocked = 0
        attempts = 0
        for u in sorted(infected):
            if u in quarantined:
                continue  # isolated host cannot spread
            for v, base, cross, external in adj.get(u, ()):
                if v in infected or v in new_infected:
                    continue
                attempts += 1
                if v in immune or v in quarantined:
                    blocked += 1
                    continue
                p = base * capability
                if cross:
                    p *= zone_factor
                if external:
                    p *= egress_factor
                if p <= 0.0:
                    continue
                draw = _draw(seed, r, u, v)
                if draw < min(1.0, p):
                    new_infected.append(v)

        blocked_total += blocked
        detected: list[str] = []
        if monitoring_p > 0.0 and infected:
            for node in sorted(infected):
                if _draw(seed, r, node, "monitor", tag="detect") < monitoring_p:
                    detected.append(node)

        for node in new_infected:
            infected.add(node)
            ever.add(node)
        for node in detected:
            infected.discard(node)

        if new_infected:
            last_infection_round = r
        if len(infected) > peak:
            peak, peak_round = len(infected), r

        timeline.append({
            "round": r,
            "new": sorted(new_infected),
            "detected": sorted(detected),
            "blocked": blocked,
            "attempts": attempts,
            "infected": len(infected),
            "cumulative": len(ever),
            "sectors": sorted({zone[n] for n in ever if n in zone}),
        })

    sectors = sorted({zone[n] for n in ever if n in zone})
    return {
        "seed": seed,
        "rounds": rounds,
        "params": {
            "capability": capability,
            "monitoring": monitoring_p,
            "segment_zones": zone_factor < 1.0,
            "egress_filter": egress_factor < 1.0,
            "immune": sorted(immune),
            "actions_applied": len(action_log),
        },
        "initial": seeds,
        "timeline": timeline,
        "action_log": action_log,
        "infected_final": sorted(infected),
        "ever_infected": sorted(ever),
        "total_infected": len(ever),
        "final_infected": len(infected),
        "peak_infected": peak,
        "peak_round": peak_round,
        "sectors_impacted": sectors,
        "blast_ratio": round(len(ever) / len(assets), 4) if assets else 0.0,
        "last_infection_round": last_infection_round,
        "contained": last_infection_round is None
                     or last_infection_round <= rounds - 2,
        "assets": len(assets),
        "blocked_attempts": blocked_total,
        "zones": {z["id"]: z["size"] for z in topology.get("zones", [])},
    }


def quick_summary(result: dict) -> dict:
    """Compact before/after view used by playbook validation."""
    return {
        "initial": len(result["initial"]),
        "total_infected": result["total_infected"],
        "final_infected": result["final_infected"],
        "peak_infected": result["peak_infected"],
        "sectors_impacted": result["sectors_impacted"],
        "blast_ratio": result["blast_ratio"],
        "contained": result["contained"],
        "last_infection_round": result["last_infection_round"],
        "blocked_attempts": result["blocked_attempts"],
    }


__all__ = ["simulate", "resolve_initial", "quick_summary", "SimulationError",
           "KNOWN_ACTIONS", "KNOWN_CONTROLS", "SEGMENT_FACTOR", "EGRESS_FACTOR"]
