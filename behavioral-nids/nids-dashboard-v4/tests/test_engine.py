import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db  # noqa: E402
from engine import run_detection, simulate  # noqa: E402
from engine.model import ALERT_THRESHOLD, Detector  # noqa: E402


@pytest.fixture(scope="module")
def det():
    rng = np.random.default_rng(0)
    return Detector().fit(simulate.normal_flows(8000, rng))


def test_scores_in_range(det):
    rng = np.random.default_rng(1)
    s = det.score(simulate.normal_flows(300, rng) + simulate.attack_flows(300, rng))
    assert s.min() >= 0 and s.max() <= 1


def test_few_false_positives(det):
    s = det.score(simulate.normal_flows(3000, np.random.default_rng(2)))
    assert np.mean(s >= ALERT_THRESHOLD) < 0.03


@pytest.mark.parametrize("kind", ["portscan", "bruteforce_ssh", "exfiltration"])
def test_attacks_detected(det, kind):
    s = det.score(simulate.attack_flows(300, np.random.default_rng(3), kind))
    assert np.mean(s >= ALERT_THRESHOLD) > 0.8


def test_explain_returns_text(det):
    f = simulate.attack_flows(1, np.random.default_rng(4), "portscan")[0]
    assert isinstance(det.explain(f), str) and len(det.explain(f)) > 10


def test_process_writes_db(det, tmp_path):
    from datetime import datetime, timezone
    path = str(tmp_path / "e.db")
    db.init_db(path)
    flows = simulate.attack_flows(5, np.random.default_rng(5), "portscan")
    with db.connect(path) as c:
        n = run_detection.process(c, det, flows, datetime.now(timezone.utc).replace(microsecond=0))
    with db.connect(path) as c:
        assert c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == n > 0
        assert c.execute("SELECT SUM(flows) FROM traffic").fetchone()[0] == 5
