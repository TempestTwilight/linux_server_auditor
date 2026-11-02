"""Streamlit dashboard for Linux Server Health & Security Auditor (Target B)."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import plotly.express as px
import streamlit as st

from linux_server_auditor.agent.ssm_injector import trigger_ec2_scenario
from linux_server_auditor.config import settings
from linux_server_auditor.dashboard import queries
from linux_server_auditor.detection.evaluation import run_full_evaluation
from linux_server_auditor.scenarios import populate_database
from linux_server_auditor.storage.database import Database

st.set_page_config(
    page_title="Linux Server Health & Security Auditor",
    page_icon="🛡️",
    layout="wide",
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DB_PATH = REPO_ROOT / settings.get("monitor", {}).get("db_path", "data/telemetry.db")
STALE_THRESHOLD_SEC = settings.get("monitor", {}).get("stale_threshold_sec", 300)

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR CONTROLS
# ─────────────────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Linux Server Auditor")
st.sidebar.caption("Academic Cloud Computing Project • Target B")

# Available instances in DB
available_instances = queries.get_available_instances(DB_PATH)
default_idx = 0
for idx, iid in enumerate(available_instances):
    if not iid.startswith("demo"):
        default_idx = idx
        break

selected_instance: str | None = None
if available_instances:
    inst_options = ["All Instances"] + available_instances
    chosen = st.sidebar.selectbox(
        "Monitored Instance",
        options=inst_options,
        index=default_idx + 1 if available_instances else 0,
        help="Select a specific EC2 instance or synthetic demo host",
    )
    if chosen != "All Instances":
        selected_instance = chosen
else:
    st.sidebar.info("No instances found in database.")

# Telemetry Sync Controls
st.sidebar.markdown("---")
st.sidebar.subheader("☁️ Telemetry Ingestion (S3)")

c_sync1, c_sync2 = st.sidebar.columns([1, 1])
if c_sync1.button("🔄 Sync S3", help="Download latest telemetry batches from AWS S3"):
    with st.spinner("Polling S3..."):
        res = queries.sync_and_detect(DB_PATH, instance_id=selected_instance)
        rec_count = res.get("records_stored", 0)
        det_anom = res.get("detection", {}).get("metric_anomalies", 0)
        st.sidebar.success(f"Synced {rec_count} records (anomalies: {det_anom})")
        time.sleep(0.5)
        st.rerun()

auto_sync = st.sidebar.checkbox(
    "⏱️ Live Auto-Refresh (15s)",
    value=False,
    help="Automatically poll S3 and refresh charts every 15 seconds",
)

# Navigation
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation",
    ["📊 Health & Telemetry", "🚨 Anomalies & Incidents", "🧪 Attack Simulation & Scenarios"],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.caption(f"Database: `{DB_PATH.name}`")
if selected_instance:
    st.sidebar.caption(f"Filter: `{selected_instance}`")

# ─────────────────────────────────────────────────────────────────────────────
# HEADER & STATUS BANNER
# ─────────────────────────────────────────────────────────────────────────────
telemetry_info = queries.get_latest_telemetry(DB_PATH, instance_id=selected_instance)
latest_ts_str = telemetry_info.get("latest_timestamp")
active_iid = telemetry_info.get("instance_id") or selected_instance or "unknown"
is_demo = bool(telemetry_info.get("is_demo") or (selected_instance and "demo" in selected_instance))

if is_demo:
    st.info("🏷️ **DEMO / TEST DATASET ACTIVE** — Showing controlled scenario benchmark data.")

# Auto-sync execution
if auto_sync:
    try:
        queries.sync_and_detect(DB_PATH, instance_id=selected_instance)
    except Exception as e:  # noqa: BLE001
        st.sidebar.warning(f"Auto-sync poll notice: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1: HEALTH & TELEMETRY OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
if page == "📊 Health & Telemetry":
    st.title("🖥️ Server Health & Telemetry Overview")
    st.markdown("Real-time system telemetry streamed from the AWS EC2 instance via S3 batching.")

    latest_metrics = queries.get_latest_metrics(DB_PATH, instance_id=selected_instance)

    if latest_ts_str:
        ts = datetime.fromisoformat(latest_ts_str)
        now = datetime.now(UTC)
        age_sec = max(0.0, (now - ts.replace(tzinfo=UTC)).total_seconds())
        is_stale = age_sec > STALE_THRESHOLD_SEC

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Monitored Host", active_iid)
        c2.metric("Last Telemetry Timestamp", ts.strftime("%Y-%m-%d %H:%M:%S UTC"))
        c3.metric(
            "Telemetry State",
            "🟢 LIVE / FRESH" if not is_stale else "🟠 STALE (>5m)",
            delta=f"{age_sec:.0f}s ago",
            delta_color="normal" if not is_stale else "inverse",
        )
        anoms = queries.get_anomalies(DB_PATH, hours=24, instance_id=selected_instance)
        c4.metric("Active Anomalies (24h)", len(anoms) if not anoms.empty else 0)

        st.markdown("### Current System Vitals")
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("CPU Utilization", f"{latest_metrics.get('cpu_percent', 0.0):.1f}%")
        m2.metric("Memory Used", f"{latest_metrics.get('memory_used_percent', 0.0):.1f}%")
        m3.metric("Swap Used", f"{latest_metrics.get('swap_used_percent', 0.0):.1f}%")
        m4.metric("Disk Used", f"{latest_metrics.get('disk_used_percent', 0.0):.1f}%")
        m5.metric("Load / Core", f"{latest_metrics.get('load_1m_per_cpu', 0.0):.2f}")
        m6.metric("Processes", f"{latest_metrics.get('process_count', 0)}")

        st.markdown("### Telemetry Trends")
        hours_filter = st.slider("Lookback Window (Hours)", min_value=1, max_value=48, value=4)
        df = queries.get_metrics_timeseries(
            DB_PATH, hours=hours_filter, instance_id=selected_instance
        )

        if not df.empty:
            # CPU & Memory
            fig_cpu = px.line(
                df,
                x="timestamp",
                y=["cpu_percent", "memory_used_percent"],
                title="CPU & Memory Utilization (%)",
                labels={"value": "Percent (%)", "variable": "Metric", "timestamp": "Timestamp"},
                color_discrete_map={"cpu_percent": "#EF553B", "memory_used_percent": "#636EFA"},
            )
            st.plotly_chart(fig_cpu, use_container_width=True)

            # Load & Network
            col_l, col_r = st.columns(2)
            with col_l:
                fig_load = px.line(
                    df,
                    x="timestamp",
                    y="load_1m_per_cpu",
                    title="System Load Average (1m Normalized per CPU)",
                    labels={"load_1m_per_cpu": "Load/CPU", "timestamp": "Timestamp"},
                )
                st.plotly_chart(fig_load, use_container_width=True)

            with col_r:
                fig_net = px.line(
                    df,
                    x="timestamp",
                    y=["network_rx_bytes_per_sec", "network_tx_bytes_per_sec"],
                    title="Network Throughput (Bytes/s)",
                    labels={"value": "Bytes/sec", "variable": "Traffic Direction"},
                )
                st.plotly_chart(fig_net, use_container_width=True)
        else:
            st.info("No time-series metric data available for the chosen window.")
    else:
        st.warning("No telemetry samples recorded in database. Click 'Sync S3' in sidebar.")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2: ANOMALIES & INCIDENTS
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🚨 Anomalies & Incidents":
    st.title("🚨 Security Incidents & Anomaly Timeline")

    # Correlated Incidents
    st.subheader("Correlated Security Incidents")
    incidents_df = queries.get_incidents(DB_PATH, instance_id=selected_instance)

    if not incidents_df.empty:
        for _, row in incidents_df.iterrows():
            badge_color = "red" if row["priority_score"] >= 8.0 else "orange"
            with st.expander(
                f":{badge_color}[●] Incident `{str(row['incident_id'])[:8]}` — Priority Score: **{row['priority_score']}** | Status: **{row['status']}** | Findings: **{row['finding_count']}**"
            ):
                st.write(f"**Host:** `{row['instance_id']}`")
                st.write(
                    f"**First Seen:** `{row['first_seen']}` | **Last Seen:** `{row['last_seen']}`"
                )
                st.write(f"**Automated Summary / Notes:** {row.get('resolution_notes') or 'N/A'}")
                if row.get("evidence"):
                    st.write("**Correlated Evidence Findings:**")
                    st.code(str(row["evidence"]), language="json")
    else:
        st.success("✅ No correlated security incidents detected.")

    st.markdown("---")
    st.subheader("Statistical & Security Rule Anomaly Detections")
    anoms_df = queries.get_anomalies(DB_PATH, hours=24, instance_id=selected_instance)

    if not anoms_df.empty:
        fig_anom = px.scatter(
            anoms_df,
            x="timestamp",
            y="score",
            color="feature",
            hover_data=["detector", "value", "threshold"],
            title="Anomaly Score Timeline (MAD, IsolationForest & Rule Triggers)",
            labels={"score": "Deviation Score", "timestamp": "Timestamp"},
        )
        st.plotly_chart(fig_anom, use_container_width=True)

        st.dataframe(
            anoms_df[
                [
                    "timestamp",
                    "instance_id",
                    "detector",
                    "feature",
                    "value",
                    "threshold",
                    "score",
                    "model_version",
                ]
            ],
            use_container_width=True,
        )
    else:
        st.success("✅ No anomalies detected in the selected time window.")

    st.markdown("---")
    st.subheader("Security Event Signals (SSH, Open Ports, FIM)")
    sec_df = queries.get_security_events(DB_PATH, hours=24, instance_id=selected_instance)
    if not sec_df.empty:
        st.dataframe(
            sec_df[["timestamp", "instance_id", "event_type", "event_data"]],
            use_container_width=True,
        )
    else:
        st.info("No raw security signals recorded in recent window.")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3: ATTACK SIMULATION & SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────
elif page == "🧪 Attack Simulation & Scenarios":
    st.title("🧪 Attack Simulation & Controlled Scenarios")
    st.markdown(
        "Demonstrate real-time detection by injecting real attacks into the live AWS EC2 instance, "
        "or evaluate detector accuracy against the controlled Target B benchmark catalog."
    )

    tab_live, tab_bench = st.tabs(
        ["☁️ Live AWS EC2 Attack Injection", "📊 Target B Ground-Truth Evaluation"]
    )

    with tab_live:
        st.subheader("Trigger Live Scenarios on AWS EC2 Instance")
        target_iid = selected_instance or settings.get("agent", {}).get(
            "instance_id", "i-0e1df82e71bf711d0"
        )
        st.write(f"Target EC2 Instance: `{target_iid}` (via AWS Systems Manager SSM)")

        cols = st.columns(2)

        with cols[0]:
            st.markdown("#### 🔥 Compute & Resource Pressure")
            if st.button("🚀 Trigger Real CPU Spike (100% for 35s)", key="btn_cpu"):
                res = trigger_ec2_scenario("cpu_spike", instance_id=target_iid)
                if res["success"]:
                    st.success(
                        f"✅ SSM Command Sent! (ID: `{res['command_id']}`). CPU burn initiated on EC2."
                    )
                    st.info(
                        "Next telemetry batch will upload to S3 in ~30s. Click 'Sync S3' or enable Auto-Refresh to see the spike!"
                    )
                else:
                    st.error(f"Failed to send SSM command: {res.get('error')}")

            if st.button("💾 Trigger Memory Allocation (450MB for 35s)", key="btn_mem"):
                res = trigger_ec2_scenario("memory_pressure", instance_id=target_iid)
                if res["success"]:
                    st.success(
                        f"✅ SSM Command Sent! (ID: `{res['command_id']}`). Memory allocated on EC2."
                    )
                else:
                    st.error(f"Failed: {res.get('error')}")

        with cols[1]:
            st.markdown("#### 🚨 Security & Integrity Attacks")
            if st.button("🚪 Open Unauthorized Listening Port 4444 (40s)", key="btn_port"):
                res = trigger_ec2_scenario("open_port", instance_id=target_iid)
                if res["success"]:
                    st.success(
                        f"✅ SSM Command Sent! (ID: `{res['command_id']}`). Port 4444 open on EC2."
                    )
                    st.caption("Expected rule trigger: `NET-001`.")
                else:
                    st.error(f"Failed: {res.get('error')}")

            if st.button("🔑 Simulate SSH Brute-Force Logins", key="btn_ssh"):
                res = trigger_ec2_scenario("ssh_brute_force", instance_id=target_iid)
                if res["success"]:
                    st.success(
                        f"✅ SSM Command Sent! (ID: `{res['command_id']}`). SSH failure signals written to journald."
                    )
                    st.caption("Expected rule trigger: `SSH-001`.")
                else:
                    st.error(f"Failed: {res.get('error')}")

            if st.button("🛡️ Tamper Watched File (/etc/hosts)", key="btn_fim"):
                res = trigger_ec2_scenario("file_tamper", instance_id=target_iid)
                if res["success"]:
                    st.success(
                        f"✅ SSM Command Sent! (ID: `{res['command_id']}`). Modified /etc/hosts (restoring in 35s)."
                    )
                    st.caption("Expected rule trigger: `FIM-001`.")
                else:
                    st.error(f"Failed: {res.get('error')}")

    with tab_bench:
        st.subheader("Target B Course Benchmark Evaluation")
        st.caption("Controlled scenarios injected with ground truth labels for accuracy scoring.")

        if st.button("⚡ Reload 7 Benchmark Scenarios & Re-evaluate"):
            with st.spinner("Populating scenarios and running detection pipeline..."):
                db = Database(DB_PATH)
                populate_database(
                    db, instance_id="demo-ec2-host", write_ground_truth=True, clear_existing=True
                )
                gt_path = REPO_ROOT / "data" / "ground_truth.csv"
                out_path = REPO_ROOT / "data" / "evaluation_summary.json"
                run_full_evaluation(DB_PATH, gt_path, out_path)
                st.success("Benchmark dataset refreshed and evaluated!")
                time.sleep(0.5)
                st.rerun()

        summary = queries.get_evaluation_summary()
        if summary:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Precision", f"{summary['overall']['precision']:.2f}")
            c2.metric("Recall", f"{summary['overall']['recall']:.2f}")
            c3.metric("F1 Score", f"{summary['overall']['f1']:.2f}")
            c4.metric(
                "Median Latency",
                f"{summary['latency']['median_seconds']}s",
                delta=f"P95: {summary['latency']['p95_seconds']}s",
            )

            st.markdown("#### Detector Performance Matrix")
            det_rows = []
            for det_name, m in summary.get("per_detector", {}).items():
                det_rows.append(
                    {
                        "Detector / Rule": det_name,
                        "TP": m["tp"],
                        "FP": m["fp"],
                        "FN": m["fn"],
                        "Precision": m["precision"],
                        "Recall": m["recall"],
                        "F1 Score": m["f1"],
                    }
                )
            if det_rows:
                st.dataframe(det_rows, use_container_width=True)

            st.markdown("#### Scenario Evaluation Breakdown")
            scen_rows = []
            for s in summary.get("scenario_results", []):
                scen_rows.append(
                    {
                        "Scenario": s["scenario"],
                        "Description": s["description"],
                        "Expected": s["expected"],
                        "Observed": ", ".join(s["observed"]),
                        "Latency": f"{s['latency_seconds']}s"
                        if s.get("latency_seconds") is not None
                        else "N/A",
                        "Status": "✅ PASS" if s["status"] == "PASS" else "❌ FAIL",
                    }
                )
            st.dataframe(scen_rows, use_container_width=True)
            st.caption(f"Caveat: {summary.get('caveat')}")
        else:
            st.info(
                "Click 'Reload 7 Benchmark Scenarios & Re-evaluate' to generate performance metrics."
            )

# Auto-refresh loop at bottom of turn
if auto_sync:
    time.sleep(15)
    st.rerun()
