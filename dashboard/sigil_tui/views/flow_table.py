"""
flow_table.py - Bidirectional conversation flow view for Sigil TUI
"""

from typing import List
from ..state import DashboardState


def render_flow_rows(state: DashboardState, max_rows: int, width: int) -> List[str]:
    """Render visible active connection flows."""
    flows = list(state.flows.values())
    if not flows:
        return ["  (No active communication flows tracked)"]

    # Sort by total packets descending
    flows.sort(key=lambda f: f.total_packets, reverse=True)

    lines = []
    lines.append(f"  {'Proto':<6} {'Conversation':<44} {'Pkts (A/B)':<14} {'Bytes':<10} {'Duration':<8} {'State'}")
    lines.append("  " + "-" * (width - 4))

    for f in flows[:max_rows - 2]:
        conv = f"{f.src_endpoint} <-> {f.dst_endpoint}"
        pkts_str = f"{f.packets_c2s}/{f.packets_s2c}"
        line = f"  {f.protocol:<6} {conv:<44} {pkts_str:<14} {f.total_bytes:<10} {f.duration:6.2f}s  {f.state}"
        lines.append(line[:width])

    return lines
