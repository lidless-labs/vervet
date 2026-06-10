"""Convert tshark JSON packet output into unified Vervet models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from api.parsers.unified import Connection, DnsQuery, Alert


SOURCE = "pcap"


def _first(value: Any) -> Any:
    """Return first value when tshark emits one-item arrays."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(_first(value)))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(_first(value))
    except (TypeError, ValueError):
        return default


def _to_timestamp(frame_layer: dict[str, Any]) -> datetime | None:
    """Convert frame epoch to timezone-aware datetime, or None if missing/invalid."""
    epoch = _to_float(frame_layer.get("frame.time_epoch"))
    if epoch is None or epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def convert_tshark_json(
    tshark_output: list[dict],
) -> tuple[list[Connection], list[DnsQuery], list[Alert]]:
    """Map tshark packets into Connection/DnsQuery/Alert models.

    Alerts are currently best-effort and usually empty for plain packet captures.
    """
    connections: list[Connection] = []
    dns_queries: list[DnsQuery] = []
    alerts: list[Alert] = []

    for idx, packet in enumerate(tshark_output):
        layers = packet.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        ip = layers.get("ip") or layers.get("ipv6") or {}
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        dns = layers.get("dns", {})

        src_ip = _first(ip.get("ip.src") or ip.get("ipv6.src"))
        dst_ip = _first(ip.get("ip.dst") or ip.get("ipv6.dst"))
        if not src_ip or not dst_ip:
            continue

        timestamp = _to_timestamp(frame)
        if timestamp is None:
            continue

        icmp = layers.get("icmp", {})
        ip_proto = _to_int(ip.get("ip.proto"), 0)

        if bool(tcp):
            proto = "tcp"
            src_port = _to_int(tcp.get("tcp.srcport"), 0)
            dst_port = _to_int(tcp.get("tcp.dstport"), 0)
        elif bool(udp):
            proto = "udp"
            src_port = _to_int(udp.get("udp.srcport"), 0)
            dst_port = _to_int(udp.get("udp.dstport"), 0)
        elif bool(icmp) or ip_proto == 1:
            proto = "icmp"
            src_port = 0
            dst_port = 0
        else:
            proto = f"ip:{ip_proto}" if ip_proto else "other"
            src_port = 0
            dst_port = 0
        frame_number = _to_int(frame.get("frame.number"), idx + 1)
        uid = f"pcap-{frame_number}"
        frame_len = _to_int(frame.get("frame.len"), 0)

        service = None
        if dst_port in (53,):
            service = "dns"
        elif dst_port in (80, 8080):
            service = "http"
        elif dst_port in (443, 8443):
            service = "tls"

        connections.append(
            Connection(
                uid=uid,
                src_ip=str(src_ip),
                src_port=src_port,
                dst_ip=str(dst_ip),
                dst_port=dst_port,
                proto=proto,
                service=service,
                duration=None,
                bytes_sent=frame_len,
                bytes_recv=None,
                timestamp=timestamp,
                tags=["pcap"],
                source=SOURCE,
                conn_state=_first(tcp.get("tcp.flags.str")) if proto == "tcp" else None,
                pkts_sent=1,
                pkts_recv=0,
            )
        )

        if dns:
            query_name = _first(dns.get("dns.qry.name")) or ""
            qtype = _first(dns.get("dns.qry.type"))
            rcode = _first(dns.get("dns.flags.rcode"))

            answers_raw = dns.get("dns.a") or dns.get("dns.aaaa") or []
            if isinstance(answers_raw, str):
                answers = [answers_raw]
            elif isinstance(answers_raw, list):
                answers = [str(item) for item in answers_raw]
            else:
                answers = []

            dns_queries.append(
                DnsQuery(
                    timestamp=timestamp,
                    src_ip=str(src_ip),
                    src_port=src_port,
                    dst_ip=str(dst_ip),
                    dst_port=dst_port,
                    query=str(query_name),
                    qtype=str(qtype) if qtype is not None else None,
                    rcode=str(rcode) if rcode is not None else None,
                    answers=answers,
                    source=SOURCE,
                )
            )

    return connections, dns_queries, alerts
