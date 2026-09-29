"""Module 4: response playbook validation - rehearse IR before going live.

A playbook is an ordered set of timed containment actions. Validation runs the
*same* simulation twice (paired draws: identical seed and per-edge uniforms)
- once bare, once with the playbook applied - and judges the difference:

    before/after blast radius, sectors impacted, containment, reduction %

The verdict is explicit: PASS (contained AND reduction >= threshold),
NOOP (nothing propagated to begin with), or FAIL with reasons.
"""

from __future__ import annotations

from .simulate import SimulationError, quick_summary, simulate

DEFAULT_THRESHOLDS = {"min_reduction": 0.5}
# min_reduction = required share of the *attainable* blast-radius reduction
# (attainable = 1 - seeded / baseline-infected), so thresholds stay meaningful
# on small topologies where the absolute maximum may be only e.g. 50%.


# -- library -----------------------------------------------------------------

LIBRARY: dict[str, dict] = {
    "beacon_containment": {
        "name": "beacon_containment",
        "description": "Isolate the beaconing host and block its C2 at round 1; "
                       "monitor the estate from round 2.",
        "actions": [
            {"round": 1, "action": "block_domain", "target": "auto"},
            {"round": 2, "action": "monitor", "value": 0.5},
        ],
        "thresholds": {"min_reduction": 0.5},
    },
    "sector_lockdown": {
        "name": "sector_lockdown",
        "description": "Segment the compromised zone immediately and patch the "
                       "most critical exposed assets.",
        "actions": [
            {"round": 1, "action": "segment_zone", "value": 0.1},
            {"round": 2, "action": "patch", "value": 3},
        ],
        "thresholds": {"min_reduction": 0.4},
    },
    "patch_and_segment": {
        "name": "patch_and_segment",
        "description": "Preventive posture: patch critical assets first, then "
                       "segment cross-zone traffic, then raise monitoring.",
        "actions": [
            {"round": 0, "action": "patch", "value": 4},
            {"round": 1, "action": "segment_zone", "value": 0.15},
            {"round": 3, "action": "monitor", "value": 0.4},
        ],
        "thresholds": {"min_reduction": 0.4},
    },
    "full_containment": {
        "name": "full_containment",
        "description": "Everything at once: isolate seeds, segment, patch, monitor.",
        "actions": [
            {"round": 0, "action": "isolate_host", "target": "auto"},
            {"round": 1, "action": "segment_zone", "value": 0.1},
            {"round": 1, "action": "patch", "value": 4},
            {"round": 2, "action": "monitor", "value": 0.6},
        ],
        "thresholds": {"min_reduction": 0.7},
    },
}


def playbook_from_detections(detections: list[dict], top: int = 3,
                             name: str = "auto_containment") -> dict:
    """Build a concrete playbook from live detections (src host / dst / SNI)."""
    actions: list[dict] = []
    seen: set[str] = set()
    for det in sorted(detections, key=lambda d: -(d.get("score") or 0))[:top]:
        src = det.get("src") or ""
        dst = det.get("dst") or ""
        sni = det.get("sni")
        host = f"host:{src.rsplit(':', 1)[0]}" if src else None
        server = f"ip:{dst.rsplit(':', 1)[0]}" if dst else None
        if host and host not in seen:
            actions.append({"round": 1, "action": "isolate_host", "target": host})
            seen.add(host)
        if server and server not in seen:
            actions.append({"round": 1, "action": "block_ip", "target": server})
            seen.add(server)
        if sni:
            actions.append({"round": 2, "action": "block_domain", "target": sni})
    if not actions:
        actions.append({"round": 1, "action": "monitor", "value": 0.5})
    return {
        "name": name,
        "description": f"Auto-generated from {len(detections)} detection(s)",
        "actions": actions,
        "thresholds": {"min_reduction": 0.5},
        "auto": True,
    }


# -- validation --------------------------------------------------------------


def _resolve_auto_targets(playbook: dict, topology: dict, result: dict) -> list[dict]:
    """Replace ``target: auto`` with the actual seeded/compromised assets.

    One ``auto`` action fans out to every applicable target (all seeds, all
    relevant domains) so containment really is containment.
    """
    seeds = set(result["initial"])
    dom_ids = set(topology.get("by_domain", {}))
    resolved = []
    for act in playbook.get("actions", []):
        if act.get("target") != "auto":
            resolved.append(dict(act))
            continue
        kind = act.get("action")
        if kind == "block_domain":
            seed_targets = {
                e["target"] for e in topology["asset_edges"]
                if e["source"] in seeds
            } | {
                e["source"] for e in topology["asset_edges"]
                if e["target"] in seeds
            }
            picks = sorted(d for d in dom_ids
                           if set(topology["by_domain"][d]) & seed_targets)
            for dom in picks:
                resolved.append({**act, "target": dom})
        elif kind in ("isolate_host", "block_ip"):
            for seed_id in sorted(seeds):
                resolved.append({**act, "target": seed_id})
        else:
            resolved.append(dict(act))
    return resolved


def validate_playbook(topology: dict, playbook: dict, **sim_kwargs) -> dict:
    """Run before/after simulation and judge the playbook."""
    if not isinstance(playbook, dict) or "actions" not in playbook:
        raise SimulationError("playbook must be a dict with an 'actions' list")
    name = playbook.get("name") or "custom"
    thresholds = {**DEFAULT_THRESHOLDS, **(playbook.get("thresholds") or {})}

    base_kwargs = dict(sim_kwargs)
    actions = playbook.get("actions") or []

    # baseline: same seeds, no actions
    probe = simulate(topology, actions=[], **base_kwargs)
    resolved = _resolve_auto_targets(playbook, topology, probe) if actions else []
    after = simulate(topology, actions=resolved, **base_kwargs)

    before = quick_summary(probe)
    aft = quick_summary(after)

    if probe["total_infected"] <= len(probe["initial"]):
        verdict_state = "noop"
        reduction = 0.0
        attainable = 0.0
        efficiency = 0.0
        reasons = ["nothing propagated without the playbook - nothing to contain"]
        passed = True
    else:
        reduction = 1.0 - (after["total_infected"] / probe["total_infected"])
        # best any playbook could do here (leave only the seeded nodes hit)
        attainable = 1.0 - (len(probe["initial"]) / probe["total_infected"])
        efficiency = (reduction / attainable) if attainable > 0 else 0.0
        reasons = []
        if not aft["contained"]:
            reasons.append(
                f"still spreading at round {aft['last_infection_round']}")
        if efficiency < thresholds["min_reduction"]:
            reasons.append(
                f"efficiency {efficiency:.0%} < required "
                f"{thresholds['min_reduction']:.0%} of attainable reduction "
                f"(absolute {reduction:.0%} of {attainable:.0%} attainable)")
        if (len(aft["sectors_impacted"]) >= len(before["sectors_impacted"])
                and not aft["contained"]):
            reasons.append("sector impact not reduced")
        verdict_state = "pass" if not reasons else "fail"
        passed = not reasons

    # which interventions actually did something
    effects = []
    for entry in after.get("action_log", []):
        effects.append({
            "round": entry["round"],
            "action": entry["action"],
            "target": entry.get("target"),
            "applied": entry["applied"],
        })

    return {
        "playbook": name,
        "description": playbook.get("description"),
        "thresholds": thresholds,
        "baseline": before,
        "after": aft,
        "reduction": round(reduction, 4),
        "attainable": round(attainable, 4),
        "efficiency": round(efficiency, 4),
        "sectors_before": before["sectors_impacted"],
        "sectors_after": aft["sectors_impacted"],
        "contained_before": before["contained"],
        "contained_after": aft["contained"],
        "verdict": {
            "state": verdict_state,
            "pass": passed,
            "reasons": reasons or ["contained with sufficient blast-radius reduction"],
        },
        "actions_resolved": resolved,
        "action_effects": effects,
        "timeline_after": after["timeline"],
        "seed": after["seed"],
    }


def evaluate_library(topology: dict, playbooks: dict | None = None,
                     **sim_kwargs) -> dict:
    """Rehearse every playbook against the same scenario and rank them."""
    lib = playbooks if playbooks is not None else LIBRARY
    results = []
    for key in sorted(lib):
        try:
            results.append(validate_playbook(topology, lib[key], **sim_kwargs))
        except SimulationError as exc:
            results.append({
                "playbook": lib[key].get("name", key),
                "verdict": {"state": "error", "pass": False, "reasons": [str(exc)]},
                "reduction": 0.0,
            })
    results.sort(key=lambda r: (
        r["verdict"]["state"] != "pass",
        -(r.get("reduction") or 0.0),
        r.get("playbook") or "",
    ))
    for rank, row in enumerate(results, start=1):
        row["rank"] = rank
    return {
        "count": len(results),
        "playbooks": results,
        "best": results[0]["playbook"] if results else None,
        "seed": sim_kwargs.get("seed", 7),
    }


__all__ = ["LIBRARY", "playbook_from_detections", "validate_playbook",
           "evaluate_library", "DEFAULT_THRESHOLDS"]
