"""Streamlit dashboard for Linux Server Health & Security Auditor (Target B)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import plotly.express as px
import streamlit as st

from linux_server_auditor.config import settings
from linux_server_auditor.dashboard import queries
from linux_server_auditor.detection.evaluation import run_full_evaluation
from linux_server_auditor.scenarios import populate_database
from linux_server_auditor.storage.database import Database

st.set_page_config(page_title="Linux Server Health & Security Auditor", layout="wide")

REPO_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = REPO_ROOT / settings.get("monitor", {}).get("db_path", "data/telemetry.db")
STALE_THRESHOLD_SEC = settings.get("monitor", {}).get("stale_threshold_sec", 300)

# Sidebar
st.sidebar.title("Linux Server Auditor")
st.sidebar.caption("Target B — Course Project Demonstration")

telemetry_info = queries.get_latest_telemetry(DB_PATH)
if telemetry_info.get("is_demo"):
    st.sidebar.info("🏷️ **DEMO DATASET ACTIVE**\nControlled test scenario data loaded.")

st.sidebar.markdown("---")
page = st.sidebar.selectbox("Navigation", ["Overview", "Anomalies & Incidents", "Evaluation"])

st.sidebar.markdown("---")
st.sidebar.subheader("Demo Controls")
if st.sidebar.button(
    "⚡ Reload Demo Scenarios", help="Populates 7 controlled test scenarios & re-evaluates"
):
    db = Database(DB_PATH)
    populate_database(db, instance_id="demo-ec2-host", write_ground_truth=True)
    gt_path = REPO_ROOT / "data" / "ground_truth.csv"
    out_path = REPO_ROOT / "data" / "evaluation_summary.json"
    run_full_evaluation(DB_PATH, gt_path, out_path)
    st.sidebar.success("Demo dataset reloaded!")
    st.rerun()

st.sidebar.markdown(f"**Database:** `{DB_PATH.name}`")
st.sidebar.markdown(f"**Host:** `{telemetry_info.get('instance_id') or 'N/A'}`")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1: OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
if page == "Overview":
    st.title("Server Health & Telemetry Overview")

    # Connectivity & Freshness
    latest_ts_str = telemetry_info.get("latest_timestamp")
    latest_metrics = queries.get_latest_metrics(DB_PATH)

    if latest_ts_str:
        ts = datetime.fromisoformat(latest_ts_str)
        now = datetime.now(UTC)
        age_sec = max(0.0, (now - ts.replace(tzinfo=UTC)).total_seconds())
        is_stale = age_sec > STALE_THRESHOLD_SEC

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Monitored Host", telemetry_info.get("instance_id") or "unknown")
        c2.metric("Last Seen (UTC)", ts.strftime("%Y-%m-%d %H:%M:%S"))
        c3.metric(
            "Telemetry State",
            "STALE" if is_stale else "FRESH",
            delta=f"{age_sec:.0f}s ago",
            delta_color="inverse" if is_stale else "normal",
        )
        anoms = queries.get_anomalies(DB_PATH, hours=24)
        c4.metric("Active Anomalies (24h)", len(anoms) if not anoms.empty else 0)

        st.markdown("### Current System Health")
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("CPU", f"{latest_metrics.get('cpu_percent', 0.0):.1f}%")
        m2.metric("Memory", f"{latest_metrics.get('memory_used_percent', 0.0):.1f}%")
        m3.metric("Swap", f"{latest_metrics.get('swap_used_percent', 0.0):.1f}%")
        m4.metric("Disk", f"{latest_metrics.get('disk_used_percent', 0.0):.1f}%")
        m5.metric("Load / Core", f"{latest_metrics.get('load_1m_per_cpu', 0.0):.2f}")
        m6.metric("Processes", f"{latest_metrics.get('process_count', 0)}")
    else:
        st.warning(
            "No telemetry records found in the database. Click **Reload Demo Scenarios** in the sidebar to populate demonstration data."
        )

    # Time-series charts
    st.markdown("---")
    st.subheader("Telemetry Time-Series")
    df = queries.get_metrics_timeseries(DB_PATH, hours=6)

    if not df.empty:
        col_left, col_right = st.columns(2)
        with col_left:
            fig_cpu = px.line(
                df,
                x="timestamp",
                y="cpu_percent",
                title="CPU Utilization (%)",
                labels={"cpu_percent": "CPU %"},
            )
            fig_cpu.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig_cpu, use_container_width=True)

            fig_disk = px.line(
                df,
                x="timestamp",
                y="disk_used_percent",
                title="Root Filesystem (%)",
                labels={"disk_used_percent": "Disk %"},
            )
            fig_disk.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig_disk, use_container_width=True)

        with col_right:
            fig_mem = px.line(
                df,
                x="timestamp",
                y=["memory_used_percent", "swap_used_percent"],
                title="Memory & Swap Utilization (%)",
                labels={"value": "Percent", "variable": "Resource"},
            )
            fig_mem.update_layout(yaxis_range=[0, 100])
            st.plotly_chart(fig_mem, use_container_width=True)

            fig_net = px.line(
                df,
                x="timestamp",
                y=["network_rx_bytes_per_sec", "network_tx_bytes_per_sec"],
                title="Network Throughput (Bytes/s)",
                labels={"value": "Bytes/s", "variable": "Interface Traffic"},
            )
            st.plotly_chart(fig_net, use_container_width=True)
    else:
        st.info("No time-series metric data available.")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2: ANOMALIES & INCIDENTS
# ─────────────────────────────────────────────────────────────────────────────
elif page == "Anomalies & Incidents":
    st.title("Anomalies & Security Incidents")

    # Correlated Incidents
    st.subheader("Correlated Incidents")
    incidents_df = queries.get_incidents(DB_PATH)

    if not incidents_df.empty:
        for _, row in incidents_df.iterrows():
            with st.expander(
                f"Incident {row['incident_id'][:8]} — Priority: {row['priority_score']} | Status: {row['status']} | Findings: {row['finding_count']}"
            ):
                st.write(f"**Host:** `{row['instance_id']}`")
                st.write(f"**First Seen:** {row['first_seen']} | **Last Seen:** {row['last_seen']}")
                st.write(f"**Priority Score:** `{row['priority_score']}`")
                st.write(f"**Resolution Notes:** {row['resolution_notes']}")
                if row.get("evidence"):
                    st.code(str(row["evidence"]), language="json")
    else:
        st.info("No correlated incidents recorded.")

    st.markdown("---")
    # Anomalies
    st.subheader("Statistical & Rule Anomalies")
    anoms_df = queries.get_anomalies(DB_PATH, hours=24)

    if not anoms_df.empty:
        fig_anom = px.scatter(
            anoms_df,
            x="timestamp",
            y="score",
            color="feature",
            hover_data=["detector", "value", "threshold"],
            title="Anomaly Score Timeline",
            labels={"score": "Deviation Score", "timestamp": "Timestamp"},
        )
        st.plotly_chart(fig_anom, use_container_width=True)

        st.dataframe(
            anoms_df[
                ["timestamp", "detector", "feature", "value", "threshold", "score", "model_version"]
            ],
            use_container_width=True,
        )
    else:
        st.success("No anomalies detected in the last 24 hours.")

    st.markdown("---")
    # Security Signals
    st.subheader("Audit & Security Signals")
    sec_df = queries.get_security_events(DB_PATH, hours=24)
    if not sec_df.empty:
        st.dataframe(sec_df[["timestamp", "event_type", "event_data"]], use_container_width=True)
    else:
        st.info("No security event signals recorded.")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3: EVALUATION
# ─────────────────────────────────────────────────────────────────────────────
elif page == "Evaluation":
    st.title("Evaluation & Ground Truth Verification")
    st.caption("Target B Course Project Requirement: Controlled scenario evaluation summary")

    summary = queries.get_evaluation_summary()
    if summary is None:
        gt_path = REPO_ROOT / "data" / "ground_truth.csv"
        out_path = REPO_ROOT / "data" / "evaluation_summary.json"
        if gt_path.exists():
            summary = run_full_evaluation(DB_PATH, gt_path, out_path)

    if summary:
        overall = summary.get("overall", {})
        latency = summary.get("latency", {})

        e1, e2, e3, e4, e5 = st.columns(5)
        e1.metric(
            "Scenarios Tested",
            f"{summary.get('passed_scenarios', 0)} / {summary.get('total_scenarios', 0)} Passed",
        )
        e2.metric("Overall Precision", f"{overall.get('precision', 0.0) * 100:.1f}%")
        e3.metric("Overall Recall", f"{overall.get('recall', 0.0) * 100:.1f}%")
        e4.metric("Overall F1 Score", f"{overall.get('f1', 0.0):.2f}")
        e5.metric("Median Latency", f"{latency.get('median_seconds', 0.0):.1f}s")

        st.markdown("### Per-Detector & Rule Performance")
        per_det = summary.get("per_detector", {})
        det_rows = []
        for det_name, stats in per_det.items():
            det_rows.append(
                {
                    "Detector / Rule ID": det_name,
                    "True Positives (TP)": stats["tp"],
                    "False Positives (FP)": stats["fp"],
                    "False Negatives (FN)": stats["fn"],
                    "Precision": f"{stats['precision']:.2f}",
                    "Recall": f"{stats['recall']:.2f}",
                    "F1 Score": f"{stats['f1']:.2f}",
                }
            )
        st.table(det_rows)

        st.markdown("### Controlled Test Scenario Outcomes")
        scen_rows = []
        for scen in summary.get("scenario_results", []):
            scen_rows.append(
                {
                    "Scenario ID": scen.get("scenario"),
                    "Description": scen.get("description"),
                    "Expected Trigger": scen.get("expected"),
                    "Observed": ", ".join(scen.get("observed", [])),
                    "Status": scen.get("status"),
                    "Latency": f"{scen.get('latency_seconds')}s"
                    if scen.get("latency_seconds") is not None
                    else "N/A",
                    "Outcome Details": scen.get("details"),
                }
            )
        st.dataframe(scen_rows, use_container_width=True)

        st.info(
            "ℹ️ **Methodology Note:** Results were obtained by evaluating controlled test conditions (baseline normal, sustained CPU spike, memory pressure, SSH brute-force, unauthorized port, watched service failure, file hash change) against labeled ground truth timestamps."
        )
    else:
        st.warning(
            "No evaluation summary found. Click **Reload Demo Scenarios** in the sidebar or run `python scripts/evaluate.py` to generate the evaluation dataset."
        )
