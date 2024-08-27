"""
telemetry.py - Real-time telemetry, sparklines, and anomaly views
"""

from typing import List
from ..state import DashboardState
from ..widgets.sparkline import render_sparkline


def render_telemetry(state: DashboardState, max_rows: int, width: int) -> List[str]:
    """Render telemetry sparklines, top talkers, and security alerts."""
    lines = []
    lines.append("=== NETWORK TELEMETRY & SYSTEM HEALTH ===")

    # Sparklines
    curr_pps = state.pps_history[-1] if state.pps_history else 0.0
    curr_mbps = state.mbps_history[-1] if state.mbps_history else 0.0
    spark_pps = render_sparkline(state.pps_history, width=35)
    spark_mbps = render_sparkline(state.mbps_history, width=35)

    lines.append(f"  Packet Rate : {curr_pps:8.1f} pps  [{spark_pps}]")
    lines.append(f"  Bandwidth   : {curr_mbps:8.3f} Mbps [{spark_mbps}]")
    lines.append(f"  Cumulative  : {state.total_packets:,} packets | {state.total_bytes / (1024*1024):.2f} MB")

    # Protocol breakdown
    lines.append("")
    lines.append("Protocol Distribution:")
    total = max(1, state.total_packets)
    for p, cnt in sorted(state.protocol_counts.items(), key=lambda x: x[1], reverse=True)[:6]:
        pct = (cnt / total) * 100.0
        bar = "#" * int(pct / 4)
        lines.append(f"  {p:<8} {cnt:8d} ({pct:5.1f}%) | {bar}")

    # Security alerts
    lines.append("")
    lines.append(f"Security & Behavioral Alerts ({len(state.alerts)}):")
    if not state.alerts:
        lines.append("  [OK] No anomalies detected. Traffic patterns nominal.")
    else:
        for al in state.alerts[-5:]:
            lines.append(f"  [{al.severity}] {al.alert_type}: {al.description}")

    return lines[:max_rows]
