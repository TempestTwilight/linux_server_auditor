"""Detection engine — runs statistical & security detectors, correlates incidents, and persists."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from linux_server_auditor.detection.correlation import correlate_findings
from linux_server_auditor.detection.isolation_forest import detect_iforest
from linux_server_auditor.detection.security_rules import evaluate_rules
from linux_server_auditor.detection.statistical import detect_mad
from linux_server_auditor.storage.database import Database
from linux_server_auditor.storage.repositories import (
    create_incident,
    get_open_incidents,
    insert_anomaly_score,
)

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]


def run_detection(db: Database, instance_id: str | None = None) -> dict[str, Any]:
    """Run all detectors over data in SQLite, correlate findings, and persist results."""
    # 1. Run Statistical (MAD) Detector on metric_samples
    metric_query = "SELECT * FROM metric_samples"
    params: list[Any] = []
    if instance_id:
        metric_query += " WHERE instance_id = ?"
        params.append(instance_id)
    metric_query += " ORDER BY timestamp ASC"

    try:
        df_metrics = pd.read_sql_query(metric_query, db.conn, params=params)
    except Exception as e:  # noqa: BLE001
        log.warning("Could not read metric_samples: %s", e)
        df_metrics = pd.DataFrame()

    metric_anomalies: list[dict[str, Any]] = []
    if not df_metrics.empty and len(df_metrics) >= 2:
        # Group by instance_id so hosts don't distort each other's baseline
        groups = (
            [df_metrics]
            if "instance_id" not in df_metrics.columns
            else [g for _, g in df_metrics.groupby("instance_id")]
        )
        for grp in groups:
            if len(grp) < 2:
                continue
            try:
                metric_anomalies.extend(detect_mad(grp))
            except Exception as e:  # noqa: BLE001
                log.warning("Error running detect_mad: %s", e)

            # Check for optional IsolationForest model
            model_paths = [
                _REPO_ROOT / "models" / "iforest_baseline.joblib",
                _REPO_ROOT / "models" / "iforest.joblib",
            ]
            for mp in model_paths:
                if mp.exists():
                    try:
                        iforest_results = detect_iforest(grp, mp)
                        metric_anomalies.extend([r for r in iforest_results if r.get("is_anomaly")])
                        break
                    except Exception as e:  # noqa: BLE001
                        log.warning("Error running detect_iforest from %s: %s", mp, e)

    # Persist metric anomalies into anomaly_scores table (avoiding duplicates)
    stored_anomalies = 0
    for anom in metric_anomalies:
        ts = str(anom["timestamp"])
        iid = str(anom["instance_id"])
        det = str(anom["detector"])
        feat = str(anom["feature"])

        # Check if already present
        exists = db.conn.execute(
            """
            SELECT 1 FROM anomaly_scores
            WHERE instance_id = ? AND timestamp = ? AND detector = ? AND feature = ?
            """,
            (iid, ts, det, feat),
        ).fetchone()

        if not exists:
            insert_anomaly_score(
                db,
                instance_id=iid,
                timestamp=ts,
                detector=det,
                feature=feat,
                value=anom.get("value") or 0.0,
                score=float(anom.get("score") or 0.0),
                threshold=float(anom.get("threshold") or 0.0),
                is_anomaly=bool(anom.get("is_anomaly")),
                model_version=str(anom.get("model_version") or "v1"),
            )
            stored_anomalies += 1

    # 2. Run Security Rules on security_events
    sec_query = "SELECT * FROM security_events"
    sec_params: list[Any] = []
    if instance_id:
        sec_query += " WHERE instance_id = ?"
        sec_params.append(instance_id)
    sec_query += " ORDER BY timestamp ASC"

    try:
        rows = db.conn.execute(sec_query, sec_params).fetchall()
        events: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("event_data"), str):
                try:
                    d["event_data"] = json.loads(d["event_data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            events.append(d)
        sec_findings = evaluate_rules(events)
    except Exception as e:  # noqa: BLE001
        log.warning("Could not evaluate security rules: %s", e)
        sec_findings = []

    # Persist security rule findings into anomaly_scores table for evaluation tracking
    for f in sec_findings:
        ts = str(f["timestamp"])
        iid = str(f["instance_id"])
        rid = str(f["rule_id"])

        exists = db.conn.execute(
            """
            SELECT 1 FROM anomaly_scores
            WHERE instance_id = ? AND timestamp = ? AND detector = 'rule' AND feature = ?
            """,
            (iid, ts, rid),
        ).fetchone()

        if not exists:
            insert_anomaly_score(
                db,
                instance_id=iid,
                timestamp=ts,
                detector="rule",
                feature=rid,
                value=1.0,
                score=1.0,
                threshold=1.0,
                is_anomaly=True,
                model_version="rules_v1",
            )
            stored_anomalies += 1

    # 3. Combine Findings for Incident Correlation
    all_findings: list[dict[str, Any]] = []

    # Add security findings directly
    for sf in sec_findings:
        all_findings.append(
            {
                "rule_id": sf["rule_id"],
                "severity": sf.get("severity", "medium"),
                "evidence": sf.get("evidence", ""),
                "explanation": sf.get("explanation", ""),
                "timestamp": sf["timestamp"],
                "instance_id": sf.get("instance_id", instance_id or "unknown"),
            }
        )

    # Convert metric anomalies into findings format
    for ma in metric_anomalies:
        score = float(ma.get("score") or 0.0)
        thresh = float(ma.get("threshold") or 1.0)
        sev = "high" if score >= 2 * thresh else "medium"
        feat = str(ma.get("feature", "unknown"))
        val = ma.get("value")
        val_str = f"{val:.1f}" if isinstance(val, (int, float)) else str(val)

        all_findings.append(
            {
                "rule_id": f"HEALTH-{feat.upper()}",
                "severity": sev,
                "evidence": f"{feat} measured {val_str} (score {score:.1f} vs threshold {thresh:.1f})",
                "explanation": f"Statistical anomaly detected on {feat} via robust MAD detector.",
                "timestamp": ma["timestamp"],
                "instance_id": ma.get("instance_id", instance_id or "unknown"),
            }
        )

    # 4. Correlate and Persist Incidents
    correlated = correlate_findings(all_findings)
    new_incidents = 0

    existing_open = get_open_incidents(db)
    for inc in correlated:
        # Check if an existing open incident matches this instance and timeframe
        iid = inc["instance_id"]
        inc_first = inc["first_seen"]
        inc_last = inc["last_seen"]

        match = None
        for ex in existing_open:
            if ex["instance_id"] == iid and ex["first_seen"] == inc_first:
                match = ex
                break

        if match:
            # Update existing incident
            db.conn.execute(
                """
                UPDATE incidents
                SET last_seen = ?, priority_score = ?, finding_count = ?, evidence = ?
                WHERE incident_id = ?
                """,
                (
                    inc_last,
                    inc["priority_score"],
                    inc["finding_count"],
                    json.dumps(inc["evidence"]),
                    match["incident_id"],
                ),
            )
        else:
            create_incident(
                db,
                instance_id=iid,
                priority_score=inc["priority_score"],
                evidence=inc["evidence"],
            )
            new_incidents += 1

    db.conn.commit()

    return {
        "metric_anomalies": len(metric_anomalies),
        "security_findings": len(sec_findings),
        "new_anomalies_stored": stored_anomalies,
        "new_incidents_created": new_incidents,
        "total_correlated_incidents": len(correlated),
    }
