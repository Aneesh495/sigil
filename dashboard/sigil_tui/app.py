"""
app.py - Main curses-based terminal application for Sigil TUI
"""

import curses
import time
from typing import Optional
from .state import DashboardState
from .stream import StreamWorker
from .views.packet_list import render_packet_rows
from .views.flow_table import render_flow_rows
from .views.inspector import render_inspector
from .views.telemetry import render_telemetry


class SigilDashboardApp:
    """Curses terminal dashboard application."""

    def __init__(self, socket_path: Optional[str] = None):
        self.state = DashboardState()
        self.worker = StreamWorker(self.state, socket_path)

    def run(self) -> None:
        """Start background worker and run curses loop."""
        self.worker.start()
        try:
            curses.wrapper(self._curses_loop)
        finally:
            self.worker.stop()

    def _curses_loop(self, stdscr: curses.window) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(100)

        # Initialize color pairs if terminal supports colors
        has_color = curses.has_colors()
        if has_color:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Header
            curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Highlight
            curses.init_pair(3, curses.COLOR_GREEN, -1)                   # Good/Telemetry
            curses.init_pair(4, curses.COLOR_YELLOW, -1)                  # Warning
            curses.init_pair(5, curses.COLOR_RED, -1)                     # Critical

        while True:
            self.state.update_rates()
            height, width = stdscr.getmaxyx()
            if height < 10 or width < 40:
                stdscr.clear()
                stdscr.addstr(0, 0, "Terminal window too small.")
                stdscr.refresh()
                time.sleep(0.1)
                continue

            stdscr.erase()

            # 1. Header Bar
            tabs = ["[1] Packets", "[2] Flows", "[3] Inspector", "[4] Telemetry"]
            tabs[self.state.active_tab] = f"*{tabs[self.state.active_tab]}*"
            status_str = "PAUSED" if self.state.is_paused else "STREAMING"
            header_text = f" SIGIL NETWORK TELEMETRY | {' '.join(tabs)} | [{status_str}]"
            header_text = header_text[:width].ljust(width)

            if has_color:
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 0, header_text)
            if has_color:
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

            # 2. Main Viewport
            body_rows = height - 3
            if self.state.active_tab == 0:
                lines, sel_offset = render_packet_rows(self.state, body_rows, width)
                for r, line in enumerate(lines[:body_rows]):
                    row_idx = 1 + r
                    if r == sel_offset and has_color:
                        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                        stdscr.addstr(row_idx, 0, line[:width].ljust(width))
                        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
                    else:
                        stdscr.addstr(row_idx, 0, line[:width])
            elif self.state.active_tab == 1:
                lines = render_flow_rows(self.state, body_rows, width)
                for r, line in enumerate(lines[:body_rows]):
                    stdscr.addstr(1 + r, 0, line[:width])
            elif self.state.active_tab == 2:
                lines = render_inspector(self.state, body_rows, width)
                for r, line in enumerate(lines[:body_rows]):
                    stdscr.addstr(1 + r, 0, line[:width])
            elif self.state.active_tab == 3:
                lines = render_telemetry(self.state, body_rows, width)
                for r, line in enumerate(lines[:body_rows]):
                    stdscr.addstr(1 + r, 0, line[:width])

            # 3. Footer Bar
            footer = " [q] Quit | [Tab/1-4] Tabs | [Up/Down] Select | [Space] Pause/Resume"
            footer = footer[:width].ljust(width)
            if has_color:
                stdscr.attron(curses.color_pair(1))
            stdscr.addstr(height - 1, 0, footer)
            if has_color:
                stdscr.attroff(curses.color_pair(1))

            stdscr.refresh()

            # Handle Keyboard Input
            try:
                ch = stdscr.getch()
            except Exception:
                ch = -1

            if ch == -1:
                continue

            if ch in (ord('q'), ord('Q'), 27):  # 'q' or ESC
                break
            elif ch == ord('\t'):
                self.state.active_tab = (self.state.active_tab + 1) % 4
            elif ch == ord('1'):
                self.state.active_tab = 0
            elif ch == ord('2'):
                self.state.active_tab = 1
            elif ch == ord('3'):
                self.state.active_tab = 2
            elif ch == ord('4'):
                self.state.active_tab = 3
            elif ch == ord(' '):
                self.state.is_paused = not self.state.is_paused
            elif ch in (curses.KEY_UP, ord('k')):
                if self.state.selected_index > 0:
                    self.state.selected_index -= 1
            elif ch in (curses.KEY_DOWN, ord('j')):
                total = len(self.state.packets)
                if self.state.selected_index < total - 1:
                    self.state.selected_index += 1
