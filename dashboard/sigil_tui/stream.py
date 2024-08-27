"""
stream.py - Background stream ingest worker for Sigil TUI dashboard
"""

import json
import socket
import threading
import time
import random
from typing import Optional
from .state import DashboardState


class StreamWorker:
    """Consumes telemetry events from Unix socket or child process."""

    def __init__(self, state: DashboardState, socket_path: Optional[str] = None):
        self.state = state
        self.socket_path = socket_path
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _run(self) -> None:
        if self.socket_path:
            self._connect_socket()
        else:
            self._run_mock_stream()

    def _connect_socket(self) -> None:
        """Connect to Unix domain socket streaming NDJSON."""
        while self.running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(self.socket_path)
                    s.settimeout(1.0)
                    buf = ""
                    while self.running:
                        try:
                            data = s.recv(4096).decode("utf-8")
                            if not data:
                                break
                            buf += data
                            while "\n" in buf:
                                line, buf = buf.split("\n", 1)
                                line = line.strip()
                                if line:
                                    parsed = json.loads(line)
                                    self.state.ingest_packet(parsed)
                        except socket.timeout:
                            continue
            except Exception:
                time.sleep(1.0)

    def _run_mock_stream(self) -> None:
        """Simulate realistic network packet stream for offline inspection."""
        hosts = ["10.0.0.1", "10.0.0.5", "192.168.1.100", "192.168.1.250", "8.8.8.8", "1.1.1.1"]
        protocols = ["TCP", "UDP", "HTTP", "DNS", "TLS", "ICMPv4"]

        pkt_id = 1
        while self.running:
            src = random.choice(hosts)
            dst = random.choice([h for h in hosts if h != src])
            proto = random.choice(protocols)
            sport = random.randint(1024, 65535) if proto in ("TCP", "UDP", "HTTP", "TLS") else 0
            dport = 80 if proto == "HTTP" else (443 if proto == "TLS" else (53 if proto == "DNS" else random.randint(1024, 65535)))
            caplen = random.choice([64, 128, 512, 1024, 1460, 1514])

            raw_dummy = bytes([random.randint(0, 255) for _ in range(min(caplen, 64))])

            pkt_dict = {
                "packet_id": pkt_id,
                "timestamp": time.time(),
                "wire_length": caplen,
                "capture_length": caplen,
                "interface": "eth0",
                "raw_hex": raw_dummy.hex(),
                "layers": [
                    {"name": "Ethernet", "header_len": 14},
                    {"name": "IPv4", "src": src, "dst": dst, "proto": 6 if proto in ("TCP", "HTTP", "TLS") else 17},
                    {"name": proto, "srcport": sport, "dstport": dport}
                ]
            }

            self.state.ingest_packet(pkt_dict)
            pkt_id += 1
            time.sleep(random.uniform(0.01, 0.05))
