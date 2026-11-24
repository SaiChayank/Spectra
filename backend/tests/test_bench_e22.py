"""Helpers of scripts/bench_e22.py (label parsing and the binary metrics used for the e22 gate)."""
import importlib.util
from pathlib import Path

_p = Path(__file__).resolve().parents[1] / "scripts" / "bench_e22.py"
_s = importlib.util.spec_from_file_location("bench_e22", _p)
B = importlib.util.module_from_spec(_s)
_s.loader.exec_module(B)


def test_c2_labels_are_oriented_inside_host_to_other_end(tmp_path):
    f = tmp_path / "x.binetflow"
    f.write_text("StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
                 "t,1,tcp,147.32.84.165,1,->,1.2.3.4,6667,S,0,0,1,1,1,flow=From-Botnet-V42-TCP-CC6-Plain-HTTP\n"
                 "t,1,tcp,5.6.7.8,80,->,147.32.84.165,2,S,0,0,1,1,1,flow=From-Botnet-V42-TCP-CC1-HTTP\n"
                 "t,1,tcp,147.32.84.165,1,->,9.9.9.9,80,S,0,0,1,1,1,flow=From-Botnet-V42-TCP-Established\n"
                 "t,1,tcp,147.32.84.165,1,->,147.32.84.1,80,S,0,0,1,1,1,flow=From-Botnet-V42-CC-internal\n")
    c2, counts = B.c2_of(str(f))
    assert c2 == {"147.32.84.165": {"1.2.3.4", "5.6.7.8"}}
    assert counts["cc_rows"] == 3 and counts["cc_rows_unoriented"] == 1


def test_binary_metrics_and_gate():
    m = B.binary([1, 1, 0, 0], [0] * 99 + [1])
    assert m["recall"] == 0.5 and m["false_alert_rate"] == 0.01 and m["false_alerts"] == 1
    assert m["recall_ci95"][0] <= 0.5 <= m["recall_ci95"][1]
    row = lambda **k: {"B": False, "P": False, "corroborated": False, "alert": False, "B_score": 0.0, "fused_score": 0.0,  # noqa: E731
                       "R": {"fires": False}, "F": {"fires": False}, "I": {"fires": False}, **k}
    pos = [row(B=True, alert=True, corroborated=True, fused_score=0.9, B_score=0.9), row(B=True, B_score=0.85), None]
    neg = [row() for _ in range(100)]
    res = B.evaluate(pos, neg, {"h1": pos[:2], "h2": [None]}, {f"n{i}": [r] for i, r in enumerate(neg)})
    assert res["fused_v3"]["pair"]["recall"] == 1 / 3 and res["v2a1_alone"]["pair"]["recall"] == 2 / 3
    assert res["fused_v3"]["host"]["recall"] == 0.5
    assert B.gate_check(res)["recall_ge_0.30_at_far_le_0.01"] is True
