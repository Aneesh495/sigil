"""
inspector.py - Protocol hierarchy and hex dump viewer for selected packet
"""

from typing import List
from ..state import DashboardState
from ..widgets.hexview import format_hex_lines


def render_inspector(state: DashboardState, max_rows: int, width: int) -> List[str]:
    """Render protocol layers tree and hex dump of selected packet."""
    pkt = state.get_selected_packet()
    if not pkt:
        return ["  (Select a packet from the packet list to inspect)"]

    lines = []
    lines.append(f"=== Packet #{pkt.packet_id} ({pkt.capture_length} bytes captured, {pkt.wire_length} wire) ===")

    # Protocol stack
    for l in pkt.layers:
        lname = l.get("name", "Unknown Layer")
        lines.append(f"  v [{lname}]")
        for k, v in l.items():
            if k != "name":
                lines.append(f"      {k}: {v}")

    # Hex Dump
    lines.append("")
    lines.append("--- Hex & ASCII Dump ---")
    raw_bytes = bytes.fromhex(pkt.raw_hex) if pkt.raw_hex else b""
    hex_lines = format_hex_lines(raw_bytes, width=16)
    for hl in hex_lines:
        lines.append("  " + hl)

    return lines[:max_rows]
