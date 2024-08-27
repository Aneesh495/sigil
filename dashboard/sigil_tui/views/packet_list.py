"""
packet_list.py - Scrolling tabular packet view for Sigil TUI
"""

from typing import List, Tuple
from ..state import DashboardState, PacketRecord


def render_packet_rows(state: DashboardState, max_rows: int, width: int) -> Tuple[List[str], int]:
    """Render visible packet rows and return lines with selected row index."""
    pkts = list(state.packets)
    if not pkts:
        return (["  (Waiting for captured packet stream...)"], -1)

    total = len(pkts)
    sel = max(0, min(state.selected_index, total - 1))

    # Adjust scroll offset to keep selected row in view
    if sel < state.scroll_offset:
        state.scroll_offset = sel
    elif sel >= state.scroll_offset + max_rows:
        state.scroll_offset = sel - max_rows + 1

    start_idx = state.scroll_offset
    end_idx = min(total, start_idx + max_rows)

    lines = []
    for i in range(start_idx, end_idx):
        pkt = pkts[i]
        src_str = f"{pkt.src}:{pkt.src_port}" if pkt.src_port else pkt.src
        dst_str = f"{pkt.dst}:{pkt.dst_port}" if pkt.dst_port else pkt.dst

        prefix = "> " if i == sel else "  "
        line = f"{prefix}{pkt.packet_id:<6} {pkt.timestamp:10.4f}  {src_str:<21} -> {dst_str:<21}  {pkt.protocol:<8} {pkt.capture_length:<6}"
        if len(line) < width:
            line = line[:width]
        lines.append(line)

    visible_selected = sel - start_idx
    return lines, visible_selected
