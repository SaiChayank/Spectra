"""Fast checks for scripts/eval_synthetic.py (the full run takes minutes and is a recorded evidence run)."""

from __future__ import annotations

import importlib.util
import os
import random

import numpy as np
import pytest

from spectra.demo import write_pcap
from spectra.features.extractor import flows_to_matrix
from spectra.tools import collect_flows

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "eval_synthetic", os.path.join(os.path.dirname(HERE), "scripts", "eval_synthetic.py"))
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


@pytest.mark.parametrize("family", list(ev.FAMILIES))
def test_each_attack_family_yields_one_flow_per_unit(tmp_path, family):
    rng = random.Random(1)
    pkts = sorted(ev.FAMILIES[family](12, rng), key=lambda p: float(p.time))
    path = write_pcap(str(tmp_path / f"{family}.pcap"), pkts)
    flows = collect_flows(path)
    # beacon_plain's last flow may split on RST; never fewer flows than units
    assert 12 <= len(flows) <= 14, (family, len(flows))
    assert flows_to_matrix(flows).shape[1] == 39


def test_generators_are_deterministic_for_a_seed():
    a = [(p.time, bytes(p)) for p in ev.beacon_tls(5, random.Random(3))]
    b = [(p.time, bytes(p)) for p in ev.beacon_tls(5, random.Random(3))]
    assert a == b


def test_bootstrap_interval_contains_the_point_and_is_reproducible():
    flags = np.array([1] * 90 + [0] * 10, dtype=float)
    r1 = ev.rate(flags, np.random.default_rng(5))
    r2 = ev.rate(flags, np.random.default_rng(5))
    assert r1 == r2
    lo, hi = r1["ci95"]
    assert lo <= r1["rate"] <= hi and 0.8 < lo and hi < 0.97
    assert ev.rate(np.zeros(50), np.random.default_rng(1))["ci95"] == [0.0, 0.0]


def test_auc_with_ci_orders_separable_and_overlapping_scores():
    rng = np.random.default_rng(2)
    sep = ev.auc_with_ci(rng.normal(5, 1, 80), rng.normal(0, 1, 80), np.random.default_rng(3))
    same = ev.auc_with_ci(rng.normal(0, 1, 80), rng.normal(0, 1, 80), np.random.default_rng(3))
    assert sep["auc"] > 0.95 and same["ci95"][0] < 0.5 < same["ci95"][1]
