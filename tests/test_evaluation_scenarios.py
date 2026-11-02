"""Tests for controlled scenarios generation and evaluation pipeline (Target B)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from linux_server_auditor.detection.evaluation import run_full_evaluation
from linux_server_auditor.scenarios import (
    SCENARIO_CATALOG,
    generate_scenario_dataset,
    populate_database,
)
from linux_server_auditor.storage.database import Database


def test_scenario_catalog_coverage():
    """Verify scenario catalog has required scenarios for Target B."""
    assert len(SCENARIO_CATALOG) >= 3
    ids = {s["id"] for s in SCENARIO_CATALOG}
    assert "SCEN-NORMAL-01" in ids
    assert "SCEN-CPU-01" in ids
    assert "SCEN-SSH-01" in ids


def test_generate_scenario_dataset():
    """Verify dataset generation returns metric samples, sec events, and ground truth."""
    metrics, sec_events, gt = generate_scenario_dataset(instance_id="test-host")
    assert len(metrics) > 100
    assert len(sec_events) >= 4
    assert len(gt) >= 5

    # Check metric record structure
    first_metric = metrics[0]
    assert first_metric["instance_id"] == "test-host"
    assert "cpu_percent" in first_metric["metrics"]
    assert "memory_used_percent" in first_metric["metrics"]
    assert "timestamp" in first_metric


def test_scenario_pipeline_and_evaluation():
    """End-to-end test of scenario population, detection, and evaluation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_eval.db"
        gt_path = Path(tmpdir) / "test_gt.csv"
        out_json = Path(tmpdir) / "test_summary.json"

        db = Database(db_path)
        summary = populate_database(
            db,
            instance_id="eval-host",
            write_ground_truth=True,
            clear_existing=True,
        )
        db.conn.close()
        assert summary["metrics_inserted"] > 0
        assert summary["scenarios_generated"] >= 5

        # Move/copy ground truth so default path isn't modified
        import shutil

        shutil.copy("data/ground_truth.csv", gt_path)

        # Evaluate against the database
        results = run_full_evaluation(
            db_path=db_path,
            gt_path=gt_path,
            output_path=out_json,
        )
        assert results["total_scenarios"] >= 5
        assert results["passed_scenarios"] >= 5
        assert results["overall"]["precision"] > 0.8
        assert results["overall"]["recall"] > 0.8
        assert out_json.exists()
