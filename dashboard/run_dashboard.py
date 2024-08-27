#!/usr/bin/env python3
"""
run_dashboard.py - Entrypoint script for Sigil terminal UI dashboard
"""

import sys
import argparse
from sigil_tui.app import SigilDashboardApp


def main():
    parser = argparse.ArgumentParser(description="Sigil Network Telemetry Terminal Dashboard")
    parser.add_argument("--socket", "-s", type=str, default=None, help="Path to Sigil IPC Unix domain socket")
    args = parser.parse_args()

    app = SigilDashboardApp(socket_path=args.socket)
    try:
        app.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
