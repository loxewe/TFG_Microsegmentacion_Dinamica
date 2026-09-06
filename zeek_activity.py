"""Lectura acotada de actividad reciente observada por Zeek."""

from collections import deque
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import time


DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_RECORDS = 2000
RECENT_WINDOW_SECONDS = 300
SUMMARY_ITEM_LIMIT = 5


def empty_activity():
    """Devuelve la estructura estable utilizada por el panel y su API."""
    return {
        "last_seen": None,
        "last_seen_epoch": None,
        "recent": False,
        "connections": 0,
        "bytes_sent": 0,
        "bytes_received": 0,
        "destinations": [],
        "dns_queries": [],
        "protocols": [],
        "external_attempts": 0,
        "peer_flows": 0,
        "mdns_events": 0,
        "ssdp_events": 0,
        "broadcast_events": 0,
        "source_status": "unavailable",
        "source_error": None,
    }


def _separator_from_header(line):
    value = line.partition(b" ")[2].strip()
    if len(value) == 4 and value.startswith(b"\\x"):
        try:
            return bytes([int(value[2:], 16)])
        except ValueError:
            return b"\t"
    return value or b"\t"


def _read_zeek_records(
    path,
    max_records=DEFAULT_MAX_RECORDS,
    max_bytes=DEFAULT_MAX_BYTES,
):
    """Lee la cola de un log TSV de Zeek sin cargar el archivo completo."""
    path = Path(path)
    if max_records <= 0 or max_bytes <= 0:
        return [], None

    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            separator = b"\t"
            fields = None
            data_start = 0
            for _ in range(256):
                line = stream.readline()
                if not line:
                    break
                if line.startswith(b"#separator "):
                    separator = _separator_from_header(line)
                elif line.startswith(b"#fields"):
                    fields = [
                        item.decode("utf-8", errors="replace")
                        for item in line.rstrip(b"\r\n").split(separator)[1:]
                    ]
                    data_start = stream.tell()
                    break

            if not fields:
                return [], "formato Zeek no reconocido"

            offset = max(data_start, size - max_bytes)
            stream.seek(offset)
            if offset > data_start:
                stream.readline()

            records = deque(maxlen=max_records)
            for line in stream:
                if not line or line.startswith(b"#"):
                    continue
                values = line.rstrip(b"\r\n").split(separator)
                if len(values) < len(fields):
                    continue
                record = {}
                for field, value in zip(fields, values):
                    decoded = value.decode("utf-8", errors="replace")
                    if decoded == "-":
                        decoded = None
                    elif decoded == "(empty)":
                        decoded = ""
                    record[field] = decoded
                records.append(record)
            return list(records), None
    except OSError as error:
        return [], str(error)


def read_zeek_records(
    path,
    max_records=DEFAULT_MAX_RECORDS,
    max_bytes=DEFAULT_MAX_BYTES,
):
    """Lee registros manteniendo la API histórica de lista."""
    records, _error = _read_zeek_records(path, max_records, max_bytes)
    return records


def _number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value):
    return max(0, int(_number(value)))


def _remember(items, value):
    if not value:
        return
    if value in items:
        items.remove(value)
    items.append(value)
    del items[:-SUMMARY_ITEM_LIMIT]


def _observe(activity, timestamp):
    if timestamp > (activity["last_seen_epoch"] or 0):
        activity["last_seen_epoch"] = timestamp


def _format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _is_multicast(address):
    try:
        return ipaddress.ip_address(address).is_multicast
    except (TypeError, ValueError):
        return False


def _broadcast_addresses(devices):
    addresses = {"255.255.255.255"}
    for device in devices:
        gateway = device.get("gateway")
        if not gateway:
            continue
        try:
            network = ipaddress.ip_network(f"{gateway}/24", strict=False)
        except ValueError:
            continue
        addresses.add(str(network.broadcast_address))
    return addresses


def format_byte_count(value):
    """Presenta un contador de bytes de forma compacta."""
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB"):
        if amount < 1024 or unit == "GB":
            decimals = 0 if unit == "B" else 1
            return f"{amount:.{decimals}f} {unit}"
        amount /= 1024


def load_device_activity(devices, log_dir, now=None):
    """Asocia la actividad reciente de conn.log y dns.log con el inventario."""
    activities = {}
    ip_to_macs = {}
    gateway_ips = set()
    for device in devices:
        mac = str(device.get("mac") or "").lower()
        if not mac:
            continue
        activities[mac] = empty_activity()
        address = device.get("ip")
        if address and address != "sin asignar":
            ip_to_macs.setdefault(address, []).append(mac)
        if device.get("gateway"):
            gateway_ips.add(device["gateway"])

    log_dir = Path(log_dir)
    managed_ips = set(ip_to_macs)
    broadcast_addresses = _broadcast_addresses(devices)
    conn_records, conn_error = _read_zeek_records(log_dir / "conn.log")
    dns_records, dns_error = _read_zeek_records(log_dir / "dns.log")
    source_errors = [error for error in (conn_error, dns_error) if error]
    if not source_errors:
        source_status = "available"
    elif len(source_errors) == 1:
        source_status = "partial"
    else:
        source_status = "unavailable"
    source_error = "; ".join(source_errors) or None
    for activity in activities.values():
        activity["source_status"] = source_status
        activity["source_error"] = source_error

    for record in conn_records:
        timestamp = _number(record.get("ts"))
        origin = record.get("id.orig_h")
        responder = record.get("id.resp_h")
        protocol = record.get("service") or record.get("proto")
        origin_bytes = _integer(record.get("orig_bytes"))
        response_bytes = _integer(record.get("resp_bytes"))
        response_port = str(record.get("id.resp_p") or "")
        transport = str(record.get("proto") or "").lower()
        is_mdns = (
            transport == "udp"
            and responder == "224.0.0.251"
            and response_port == "5353"
        )
        is_ssdp = (
            transport == "udp"
            and responder == "239.255.255.250"
            and response_port == "1900"
        )
        is_broadcast = responder in broadcast_addresses

        for mac in ip_to_macs.get(origin, ()):
            activity = activities[mac]
            activity["connections"] += 1
            activity["bytes_sent"] += origin_bytes
            activity["bytes_received"] += response_bytes
            _observe(activity, timestamp)
            _remember(activity["destinations"], responder)
            _remember(activity["protocols"], protocol)
            if responder in managed_ips:
                activity["peer_flows"] += 1
            elif is_mdns:
                activity["mdns_events"] += 1
            elif is_ssdp:
                activity["ssdp_events"] += 1
            elif is_broadcast:
                activity["broadcast_events"] += 1
            elif responder not in gateway_ips and not _is_multicast(responder):
                activity["external_attempts"] += 1

        for mac in ip_to_macs.get(responder, ()):
            activity = activities[mac]
            activity["connections"] += 1
            activity["bytes_sent"] += response_bytes
            activity["bytes_received"] += origin_bytes
            _observe(activity, timestamp)
            _remember(activity["destinations"], origin)
            _remember(activity["protocols"], protocol)
            if origin in managed_ips:
                activity["peer_flows"] += 1

    for record in dns_records:
        timestamp = _number(record.get("ts"))
        origin = record.get("id.orig_h")
        for mac in ip_to_macs.get(origin, ()):
            activity = activities[mac]
            _observe(activity, timestamp)
            _remember(activity["dns_queries"], record.get("query"))

    reference_time = time.time() if now is None else now
    for activity in activities.values():
        timestamp = activity["last_seen_epoch"]
        if timestamp is not None:
            activity["last_seen"] = _format_timestamp(timestamp)
            activity["recent"] = 0 <= reference_time - timestamp <= (
                RECENT_WINDOW_SECONDS
            )
    return activities
