"""
test_dashboard_state.py - Unit tests for Sigil dashboard state, widgets, and views
"""

import unittest
import time
from sigil_tui.state import DashboardState
from sigil_tui.widgets.sparkline import render_sparkline
from sigil_tui.widgets.hexview import format_hex_lines
from sigil_tui.views.packet_list import render_packet_rows
from sigil_tui.views.flow_table import render_flow_rows
from sigil_tui.views.inspector import render_inspector
from sigil_tui.views.telemetry import render_telemetry


class TestDashboardState(unittest.TestCase):

    def setUp(self):
        self.state = DashboardState(max_packets=100)

    def test_packet_ingestion_and_flow_aggregation(self):
        pkt1 = {
            "packet_id": 1,
            "timestamp": 1000.0,
            "wire_length": 64,
            "capture_length": 64,
            "interface": "eth0",
            "raw_hex": "4500003c00010000400600000a0000010a000002",
            "layers": [
                {"name": "IPv4", "src": "10.0.0.1", "dst": "10.0.0.2"},
                {"name": "TCP", "srcport": 50000, "dstport": 80}
            ]
        }
        self.state.ingest_packet(pkt1)
        self.assertEqual(self.state.total_packets, 1)
        self.assertEqual(self.state.total_bytes, 64)
        self.assertEqual(self.state.protocol_counts.get("TCP"), 1)

        # Ingest return packet (s2c)
        pkt2 = {
            "packet_id": 2,
            "timestamp": 1000.05,
            "wire_length": 128,
            "capture_length": 128,
            "interface": "eth0",
            "raw_hex": "4500008000020000400600000a0000020a000001",
            "layers": [
                {"name": "IPv4", "src": "10.0.0.2", "dst": "10.0.0.1"},
                {"name": "TCP", "srcport": 80, "dstport": 50000}
            ]
        }
        self.state.ingest_packet(pkt2)
        self.assertEqual(self.state.total_packets, 2)

        # Verify flow was unified into single bidirectional flow
        self.assertEqual(len(self.state.flows), 1)
        flow = list(self.state.flows.values())[0]
        self.assertEqual(flow.total_packets, 2)
        self.assertEqual(flow.total_bytes, 192)
        self.assertAlmostEqual(flow.duration, 0.05, places=3)

    def test_sparkline_widget(self):
        # Empty
        self.assertEqual(render_sparkline([], width=5), "     ")

        # Flat values
        flat = render_sparkline([10.0, 10.0, 10.0], width=3)
        self.assertEqual(len(flat), 3)

        # Rising slope
        rising = render_sparkline([0.0, 25.0, 50.0, 75.0, 100.0], width=5)
        self.assertEqual(len(rising), 5)
        self.assertEqual(rising[0], " ")
        self.assertEqual(rising[-1], "█")

    def test_hexview_widget(self):
        data = b"ABCDEFGH12345678"
        lines = format_hex_lines(data, width=16)
        self.assertEqual(len(lines), 1)
        self.assertIn("00000000", lines[0])
        self.assertIn("41 42 43 44", lines[0])
        self.assertIn("|ABCDEFGH12345678|", lines[0])

    def test_views_rendering(self):
        pkt = {
            "packet_id": 10,
            "timestamp": 2000.0,
            "wire_length": 40,
            "capture_length": 40,
            "interface": "eth0",
            "raw_hex": "010203040506",
            "layers": [{"name": "IPv4", "src": "192.168.1.1", "dst": "192.168.1.2"}]
        }
        self.state.ingest_packet(pkt)

        # Packet list view
        lines, sel = render_packet_rows(self.state, max_rows=10, width=80)
        self.assertTrue(any("192.168.1.1" in l for l in lines))

        # Inspector view
        insp = render_inspector(self.state, max_rows=15, width=80)
        self.assertTrue(any("Packet #10" in l for l in insp))

        # Telemetry view
        telem = render_telemetry(self.state, max_rows=20, width=80)
        self.assertTrue(any("Packet Rate" in l for l in telem))


if __name__ == "__main__":
    unittest.main()
