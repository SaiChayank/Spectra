"""Detect attempts to live beside the detection boundary (Module 3).

A signature of detector gaming is a suspicious pile-up of scores *just below*
the detection threshold: the attacker shapes traffic to be as loud as
possible without crossing the line. Benign traffic does not know where the
line is, so its score distribution is smooth across the band.

Two complementary checks over a sliding window of recent scores:

  * near-miss rate  - fraction of scores in [boundary-band, boundary)
  * boundary spike  - the just-below bin holds far more mass than the
                      next-lower bin (a cliff that should not exist)
"""

from __future__ import annotations

from collections import deque

BAND = 15.0            # points below the boundary considered "near-miss"
MIN_WINDOW = 40        # scores required before judging
RATE_TRIGGER = 0.45    # >=45% near-miss is suspicious on its own
SPIKE_RATIO = 2.5      # just-below bin must dwarf the next-lower bin


def score_boundary(contamination: float) -> float:
    """Approximate 0-100 score at which detection triggers.

    Scores are percentile ranks against the training set, and the raw
    threshold sits at the (1-contamination) quantile of that same set, so the
    score-space boundary is ~100*(1-contamination).
    """
    return max(50.0, min(99.5, 100.0 * (1.0 - contamination)))


def watch(scores, contamination: float = 0.02,
          band: float = BAND) -> dict:
    """Analyse a sequence of 0-100 scores for threshold-hugging behaviour."""
    vals = list(scores)
    if len(vals) < MIN_WINDOW:
        return {"available": False, "n": len(vals),
                "reason": f"need >= {MIN_WINDOW} scores"}

    boundary = score_boundary(contamination)
    near_lo = boundary - band
    recent = vals[-250:]

    near = [s for s in recent if near_lo <= s < boundary]
    far = [s for s in recent if s < near_lo]
    above = [s for s in recent if s >= boundary]
    near_rate = len(near) / len(recent)

    # bin comparison: [boundary-5, boundary) vs [boundary-10, boundary-5)
    top_bin = sum(1 for s in recent if boundary - 5 <= s < boundary)
    next_bin = sum(1 for s in recent if boundary - 10 <= s < boundary - 5)
    spike = (top_bin / max(1, next_bin)) if next_bin else float(top_bin)

    expected = band / 100.0  # ~0.15 of a uniform score distribution
    reasons = []
    if near_rate >= RATE_TRIGGER and near_rate >= 2.2 * expected:
        reasons.append(
            f"{near_rate:.0%} of recent scores sit in the "
            f"[{near_lo:.0f},{boundary:.0f}) near-miss band "
            f"(expected ~{expected:.0%})")
    if spike >= SPIKE_RATIO and top_bin >= 5:
        reasons.append(
            f"score cliff: the top near-miss bin holds {top_bin} scores vs "
            f"{next_bin} one bin lower (x{spike:.1f})")
    if len(far) < len(recent) * 0.05 and near_rate >= RATE_TRIGGER:
        reasons.append(
            "almost no low-score traffic in the window - distribution "
            "looks censored rather than natural")

    return {
        "available": True,
        "n": len(recent),
        "boundary": round(boundary, 1),
        "near_miss_rate": round(near_rate, 4),
        "expected_rate": round(expected, 4),
        "above_boundary_rate": round(len(above) / len(recent), 4),
        "spike_ratio": round(spike, 2),
        "suspected": bool(reasons),
        "reasons": reasons,
    }


class ScoreWindow:
    """Sliding window of recent scores wired into the engine loop."""

    def __init__(self, contamination: float = 0.02, maxlen: int = 1000):
        self.scores: deque[float] = deque(maxlen=maxlen)
        self.contamination = contamination
        self.alerted = False

    def add(self, score: float) -> dict | None:
        """Add one score; returns the watch report when a new alert fires."""
        self.scores.append(float(score))
        report = watch(self.scores, contamination=self.contamination)
        if report.get("suspected") and not self.alerted:
            self.alerted = True
            return report
        if not report.get("suspected"):
            self.alerted = False
        return None

    def report(self) -> dict:
        return watch(self.scores, contamination=self.contamination)
