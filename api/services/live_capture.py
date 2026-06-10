"""
Live PCAP Capture Service.

Manages tcpdump/tshark capture sessions for real-time traffic analysis.
Captures are written to temp files and ingested when stopped.
"""
import os
import signal
import subprocess
import tempfile
import logging
import time
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class CaptureSession:
    """Represents an active or completed capture session."""
    session_id: str
    interface: str
    capture_filter: str
    started_at: float
    stopped_at: Optional[float] = None
    pcap_path: str = ""
    packet_count: int = 0
    file_size_bytes: int = 0
    status: str = "running"  # running, stopped, error, ingested
    pid: Optional[int] = None
    error: str = ""


class LiveCaptureService:
    """Manages live packet capture sessions."""

    def __init__(self):
        self._sessions: Dict[str, CaptureSession] = {}
        self._processes: Dict[str, subprocess.Popen] = {}
        self._timers: Dict[str, threading.Timer] = {}
        self._capture_dir = tempfile.mkdtemp(prefix="vervet_capture_")

    def get_interfaces(self) -> list:
        """List available network interfaces."""
        try:
            result = subprocess.run(
                ["ip", "-j", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                import json
                interfaces = json.loads(result.stdout)
                return [
                    {
                        "name": iface.get("ifname", ""),
                        "state": iface.get("operstate", "UNKNOWN"),
                        "mtu": iface.get("mtu", 0),
                    }
                    for iface in interfaces
                ]
        except Exception as e:
            logger.warning(f"Failed to list interfaces: {e}")

        # Fallback
        try:
            result = subprocess.run(
                ["ls", "/sys/class/net"],
                capture_output=True, text=True, timeout=5,
            )
            return [{"name": n.strip(), "state": "unknown", "mtu": 0}
                    for n in result.stdout.split() if n.strip()]
        except Exception:
            return [{"name": "eth0", "state": "unknown", "mtu": 0}]

    def start_capture(
        self,
        interface: str = "any",
        capture_filter: str = "",
        max_packets: int = 10000,
        max_seconds: int = 300,
    ) -> CaptureSession:
        """Start a live packet capture."""
        session_id = f"cap_{int(time.time())}_{len(self._sessions)}"
        pcap_path = os.path.join(self._capture_dir, f"{session_id}.pcap")

        # Build tcpdump command
        cmd = ["tcpdump", "-i", interface, "-w", pcap_path, "-c", str(max_packets)]
        if capture_filter:
            cmd.extend(["--", capture_filter])

        session = CaptureSession(
            session_id=session_id,
            interface=interface,
            capture_filter=capture_filter,
            started_at=time.time(),
            pcap_path=pcap_path,
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            session.pid = proc.pid
            self._processes[session_id] = proc
            self._sessions[session_id] = session
            logger.info(f"Started capture {session_id} on {interface} (PID {proc.pid})")

            # Enforce max_seconds timeout
            if max_seconds > 0:
                timer = threading.Timer(max_seconds, self._timeout_stop, args=[session_id])
                timer.daemon = True
                timer.start()
                self._timers[session_id] = timer

        except FileNotFoundError:
            session.status = "error"
            session.error = "tcpdump not found. Install with: apt install tcpdump"
            self._sessions[session_id] = session

        except PermissionError:
            session.status = "error"
            session.error = "Permission denied. tcpdump may require root/CAP_NET_RAW"
            self._sessions[session_id] = session

        except Exception as e:
            session.status = "error"
            session.error = str(e)
            self._sessions[session_id] = session

        return session

    def _timeout_stop(self, session_id: str):
        """Called by timer when max_seconds expires."""
        logger.info(f"Capture {session_id} reached max time limit, stopping")
        self.stop_capture(session_id)

    def stop_capture(self, session_id: str) -> Optional[CaptureSession]:
        """Stop a running capture session."""
        session = self._sessions.get(session_id)
        if not session:
            return None

        # Cancel timeout timer if active
        timer = self._timers.pop(session_id, None)
        if timer:
            timer.cancel()

        proc = self._processes.get(session_id)
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        session.stopped_at = time.time()
        session.status = "stopped"

        # Get file stats
        if os.path.exists(session.pcap_path):
            session.file_size_bytes = os.path.getsize(session.pcap_path)

        # Try to get packet count
        try:
            result = subprocess.run(
                ["capinfos", "-c", session.pcap_path],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.split("\n"):
                if "Number of packets" in line:
                    session.packet_count = int(line.split(":")[-1].strip())
        except Exception:
            pass

        return session

    def get_session(self, session_id: str) -> Optional[CaptureSession]:
        """Get capture session info."""
        session = self._sessions.get(session_id)
        if session and session.status == "running":
            proc = self._processes.get(session_id)
            if proc and proc.poll() is not None:
                session.status = "stopped"
                session.stopped_at = time.time()
                if os.path.exists(session.pcap_path):
                    session.file_size_bytes = os.path.getsize(session.pcap_path)
        return session

    def list_sessions(self) -> list:
        """List all capture sessions."""
        # Update statuses
        for sid in list(self._sessions.keys()):
            self.get_session(sid)
        return list(self._sessions.values())

    def get_pcap_path(self, session_id: str) -> Optional[str]:
        """Get the pcap file path for a stopped capture."""
        session = self._sessions.get(session_id)
        if session and session.pcap_path and os.path.exists(session.pcap_path):
            return session.pcap_path
        return None

    def cleanup(self, session_id: str):
        """Clean up a capture session's files."""
        session = self._sessions.get(session_id)
        if session and session.pcap_path and os.path.exists(session.pcap_path):
            os.remove(session.pcap_path)
        if session_id in self._processes:
            del self._processes[session_id]
        if session_id in self._sessions:
            del self._sessions[session_id]
