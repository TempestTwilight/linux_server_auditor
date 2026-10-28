"""Streamlit dashboard — 3 pages: Overview, Anomalies, Evaluation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st
import plotly.express as px

from linux_server_auditor.config import settings
from linux_server_auditor.dashboard import queries

st.set_page_config(page_title="Linux Server Auditor", layout="wide")

DB_PATH = Path(settings["monitor"]["db_path"])
STALE_THRESHOLD_SEC = settings["monitor"]["stale_threshold_sec"]

# Navigation
page = st.sidebar.selectbox("Page", ["Overview", "Anomalies & Incidents", "Evaluation"])

if page == "Overview":
    st.title("System Overview")
    
    # Connectivity
    latest = queries.get_latest_telemetry(DB_PATH)
    if latest["latest_timestamp"]:
        ts = datetime.fromisoformat(latest["latest_timestamp"])
        now = datetime.now(timezone.utc)
        age_sec = (now - ts.replace(tzinfo=timezone.utc)).total_seconds()
        stale = age_sec > STALE_THRESHOLD_SEC
        
        col1, col2 = st.columns(2)
        col1.metric("Latest Telemetry", ts.strftime("%Y-%m-%d %H:%M:%S"))
        col2.metric("Status", "STALE" if stale else "FRESH",
                    delta=f"{age_sec:.0f}s ago",
                    delta_color="inverse" if stale else "off")
    else:
        st.warning("No telemetry data available")
    
    # Metrics timeseries
    df = queries.get_metrics_timeseries(DB_PATH, hours=6)
    if not df.empty:
        st.subheader("System Metrics (Last 6 Hours)")
        
        fig_cpu = px.line(df, x="timestamp", y="cpu_percent", title="CPU %")
        st.plotly_chart(fig_cpu, use_container_width=True)
        
        fig_mem = px.line(df, x="timestamp", y="memory_used_percent", title="Memory %")
        st.plotly_chart(fig_mem, use_container_width=True)
        
        fig_disk = px.line(df, x="timestamp", y="disk_used_percent", title="Disk %")
        st.plotly_chart(fig_disk, use_container_width=True)
        
        fig_net = px.line(df, x="timestamp",
                         y=["network_rx_bytes_per_sec", "network_tx_bytes_per_sec"],
                         title="Network (bytes/sec)")
        st.plotly_chart(fig_net, use_container_width=True)
    else:
        st.info("No metric data in the last 6 hours")

elif page == "Anomalies & Incidents":
    st.title("Anomalies & Incidents")
    
    # Anomalies
    st.subheader("Anomalies (Last 24 Hours)")
    anom_df = queries.get_anomalies(DB_PATH, hours=24)
    if not anom_df.empty:
        st.dataframe(anom_df, use_container_width=True)
        
        # Timeline
        fig = px.scatter(anom_df, x="timestamp", y="score", color="feature",
                        hover_data=["detector", "value", "threshold"],
                        title="Anomaly Timeline")
        fig.add_hline(y=anom_df["threshold"].mean(), line_dash="dash",
                     annotation_text="Avg Threshold")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No anomalies detected")
    
    # Security events
    st.subheader("Security Events (Last 24 Hours)")
    sec_df = queries.get_security_events(DB_PATH, hours=24)
    if not sec_df.empty:
        st.dataframe(sec_df, use_container_width=True)
    else:
        st.info("No security events")
    
    # Incidents
    st.subheader("Incidents")
    inc_df = queries.get_incidents(DB_PATH)
    if not inc_df.empty:
        st.dataframe(inc_df, use_container_width=True)
    else:
        st.info("No incidents")

elif page == "Evaluation":
    st.title("Evaluation Results")
    st.info("Evaluation metrics will be populated after running the evaluation suite.")
    
    st.markdown("""
    ### Metrics to Display
    - **Detection Performance**: Precision, Recall, F1 (event-level and window-level)
    - **False Alert Rate**: Alerts per hour during normal operation
    - **Detection Latency**: Median and p95 time from condition start to alert
    - **Agent Overhead**: CPU and RAM usage on monitored instance
    - **Telemetry Loss**: Percentage of samples lost in transit
    
    Results will be loaded from the evaluation output after running the test suite.
    """)
