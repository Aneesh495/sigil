"""
state.py - Thread-safe state model for Sigil TUI dashboard
"""

from dataclasses import dataclass, field
from collections import deque
import threading
import time
from typing import Dict, List, Optional, Any


@dataclass
class PacketRecord:
    packet_id: int
    timestamp: float
    wire_length: int
    capture_length: int
    interface: str
    src: str
    dst: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    info: str
    raw_hex: str
    layers: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class FlowRecord:
    canonical_id: str
    protocol: str
    src_endpoint: str
    dst_endpoint: str
    packets_c2s: int = 0
    packets_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    start_time: float = 0.0
    last_time: float = 0.0
    state: str = "ESTABLISHED"
    app_protocol: str = "unknown"

    @property
    def total_packets(self) -> int:
        return self.packets_c2s + self.packets_s2c

    @property
    def total_bytes(self) -> int:
        return self.bytes_c2s + self.bytes_s2c

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)


@dataclass
class AlertRecord:
    timestamp: float
    severity: str
    alert_type: str
    description: str
    src: str
    dst: str


class DashboardState:
    """Thread-safe state container tracking packet streams and telemetry."""

    def __init__(self, max_packets: int = 5000):
        self._lock = threading.Lock()
        self.max_packets = max_packets

        # Packets ring
        self.packets: deque[PacketRecord] = deque(maxlen=max_packets)
        self.filtered_packets: List[PacketRecord] = []
        self.selected_index: int = 0
        self.scroll_offset: int = 0

        # Flows table
        self.flows: Dict[str, FlowRecord] = {}

        # Rates and metrics history (one sample per second)
        self.pps_history: deque[float] = deque(maxlen=60)
        self.mbps_history: deque[float] = deque(maxlen=60)
        self.total_packets: int = 0
        self.total_bytes: int = 0

        # Protocol counts
        self.protocol_counts: Dict[str, int] = {}

        # Alerts
        self.alerts: List[AlertRecord] = []

        # UI controls
        self.active_tab: int = 0  # 0: Packets, 1: Flows, 2: Inspector, 3: Telemetry
        self.is_paused: bool = False
        self.filter_query: str = ""

        # Rate tracking variables
        self._last_calc_time = time.time()
        self._pkts_in_window = 0
        self._bytes_in_window = 0

    def ingest_packet(self, data: Dict[str, Any]) -> None:
        """Ingest raw dictionary packet event into state."""
        with self._lock:
            if self.is_paused:
                return

            pkt_id = data.get("packet_id", self.total_packets + 1)
            ts = data.get("timestamp", time.time())
            wire_len = data.get("wire_length", 64)
            cap_len = data.get("capture_length", 64)
            iface = data.get("interface", "unknown")

            # Extract fields
            src = "unknown"
            dst = "unknown"
            src_port = None
            dst_port = None
            proto = "RAW"
            info = f"{cap_len} bytes"
            raw_hex = data.get("raw_hex", "")
            layers = data.get("layers", [])

            for layer in layers:
                lname = layer.get("name", "")
                if lname in ("IPv4", "IPv6"):
                    src = layer.get("src", src)
                    dst = layer.get("dst", dst)
                elif lname in ("TCP", "UDP"):
                    src_port = layer.get("srcport")
                    dst_port = layer.get("dstport")
                    proto = lname
                elif lname not in ("Ethernet", "VLAN"):
                    proto = lname

            rec = PacketRecord(
                packet_id=pkt_id,
                timestamp=ts,
                wire_length=wire_len,
                capture_length=cap_len,
                interface=iface,
                src=src,
                dst=dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                info=info,
                raw_hex=raw_hex,
                layers=layers
            )

            self.packets.append(rec)
            self.total_packets += 1
            self.total_bytes += cap_len
            self._pkts_in_window += 1
            self._bytes_in_window += cap_len

            # Update protocol counts
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

            # Update flows
            if src != "unknown" and dst != "unknown":
                ep1 = f"{src}:{src_port or 0}"
                ep2 = f"{dst}:{dst_port or 0}"
                first, second = (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)
                fid = f"{proto} {first} <-> {second}"

                if fid not in self.flows:
                    self.flows[fid] = FlowRecord(
                        canonical_id=fid,
                        protocol=proto,
                        src_endpoint=ep1,
                        dst_endpoint=ep2,
                        start_time=ts,
                        last_time=ts
                    )

                flow = self.flows[fid]
                flow.last_time = ts
                if ep1 == flow.src_endpoint:
                    flow.packets_c2s += 1
                    flow.bytes_c2s += cap_len
                else:
                    flow.packets_s2c += 1
                    flow.bytes_s2c += cap_len

    def update_rates(self) -> None:
        """Periodic rate calculator called every tick."""
        with self._lock:
            now = time.time()
            dt = now - self._last_calc_time
            if dt >= 1.0:
                pps = self._pkts_in_window / dt
                mbps = (self._bytes_in_window * 8.0) / (dt * 1_000_000.0)

                self.pps_history.append(pps)
                self.mbps_history.append(mbps)

                self._pkts_in_window = 0
                self._bytes_in_window = 0
                self._last_calc_time = now

    def get_selected_packet(self) -> Optional[PacketRecord]:
        """Retrieve packet currently highlighted in packet list."""
        with self._lock:
            pkts = self.filtered_packets if self.filter_query else list(self.packets)
            if 0 <= self.selected_index < len(pkts):
                return pkts[self.selected_index]
            return None
