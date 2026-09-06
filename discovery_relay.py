"""Relay controlado de descubrimiento local para clientes Wi-Fi aislados.

El punto de acceso impide el reenvio directo entre estaciones. Este proceso
recibe la copia destinada al host y vuelve a emitir solamente mDNS, SSDP o
broadcast IPv4 cuando la politica del dispositivo emisor lo permite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal
import socket
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path


DEFAULT_INTERFACE = "phy0-ap0"
DEFAULT_RELOAD_INTERVAL = 2.0
DEFAULT_RATE_LIMIT = 20
PACKET_OUTGOING = getattr(socket, "PACKET_OUTGOING", 4)
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_EAPOL = 0x888E
BROADCAST_MAC = b"\xff" * 6
MDNS_MAC = bytes.fromhex("01005e0000fb")
SSDP_MAC = bytes.fromhex("01005e7ffffa")
MDNS_IP = socket.inet_aton("224.0.0.251")
SSDP_IP = socket.inet_aton("239.255.255.250")
MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
INTERFACE_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")


def normalize_mac(value):
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    return normalized if MAC_PATTERN.fullmatch(normalized) else None


def mac_from_bytes(value):
    return ":".join(f"{part:02x}" for part in value)


@dataclass(frozen=True)
class RelayDecision:
    protocol: str
    source_mac: str
    source_ip: str


def classify_frame(frame):
    """Clasifica solo los paquetes que el relay puede volver a emitir."""
    if len(frame) < 14:
        return None
    destination_mac = frame[0:6]
    source_mac = mac_from_bytes(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type in (ETH_P_ARP, ETH_P_IPV6, ETH_P_EAPOL):
        return None
    if ether_type != ETH_P_IP or len(frame) < 34:
        return None

    ip_offset = 14
    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or len(frame) < ip_offset + header_length:
        return None
    fragment = struct.unpack("!H", frame[ip_offset + 6 : ip_offset + 8])[0]
    if fragment & 0x3FFF:
        return None
    if frame[ip_offset + 9] != socket.IPPROTO_UDP:
        return None

    udp_offset = ip_offset + header_length
    if len(frame) < udp_offset + 8:
        return None
    source_port, destination_port = struct.unpack(
        "!HH", frame[udp_offset : udp_offset + 4]
    )
    destination_ip = frame[ip_offset + 16 : ip_offset + 20]
    source_ip = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])

    if (
        destination_mac == MDNS_MAC
        and destination_ip == MDNS_IP
        and destination_port == 5353
    ):
        return RelayDecision("mdns", source_mac, source_ip)
    if (
        destination_mac == SSDP_MAC
        and destination_ip == SSDP_IP
        and destination_port == 1900
    ):
        return RelayDecision("ssdp", source_mac, source_ip)
    if destination_mac != BROADCAST_MAC:
        return None
    if source_port in (67, 68) or destination_port in (67, 68):
        return None
    if destination_ip == b"\xff\xff\xff\xff" or destination_ip[-1] == 255:
        return RelayDecision("broadcast", source_mac, source_ip)
    return None


class PolicyStore:
    """Vista fail-closed de las politicas de los dispositivos activos."""

    def __init__(self, policy_path, database_path, reload_interval=2.0):
        self.policy_path = Path(policy_path)
        self.database_path = Path(database_path)
        self.reload_interval = float(reload_interval)
        self.permissions = {}
        self.last_reload = 0.0
        self.last_error = None

    def refresh(self, now=None, force=False):
        now = time.monotonic() if now is None else now
        if not force and now - self.last_reload < self.reload_interval:
            return False
        self.last_reload = now
        try:
            policies = json.loads(self.policy_path.read_text(encoding="utf-8"))
            database = json.loads(self.database_path.read_text(encoding="utf-8"))
            self.permissions = self._build_permissions(policies, database)
            self.last_error = None
        except (OSError, ValueError, TypeError) as error:
            self.permissions = {}
            self.last_error = str(error)
        return True

    @staticmethod
    def _build_permissions(policies, database):
        if not isinstance(policies, dict) or not isinstance(database, dict):
            raise ValueError("policies.json y database.json deben ser objetos")
        default = policies.get("default", {})
        overrides = policies.get("devices", {})
        if not isinstance(default, dict) or not isinstance(overrides, dict):
            raise ValueError("estructura de policies.json no valida")
        permissions = {}
        for raw_mac, device in database.items():
            mac = normalize_mac(raw_mac)
            if not mac or not isinstance(device, dict) or not device.get("creada"):
                continue
            override = overrides.get(mac, overrides.get(raw_mac, {}))
            if not isinstance(override, dict):
                raise ValueError(f"politica no valida para {mac}")
            try:
                client_ip = socket.inet_ntoa(
                    socket.inet_aton(device.get("ip_cliente", ""))
                )
            except OSError:
                continue
            policy = dict(default)
            policy.update(override)
            permissions[mac] = {
                "client_ip": client_ip,
                "mdns": policy.get("mdns") is True,
                "ssdp": policy.get("ssdp") is True,
                "broadcast": policy.get("broadcast")
                if policy.get("broadcast") in ("allow", "log")
                else "block",
            }
        return permissions

    def decision_allowed(self, decision):
        policy = self.permissions.get(decision.source_mac)
        if not policy or policy["client_ip"] != decision.source_ip:
            return False
        if decision.protocol == "broadcast":
            return policy["broadcast"] in ("allow", "log")
        return policy.get(decision.protocol) is True

    def should_log_broadcast(self, decision):
        policy = self.permissions.get(decision.source_mac, {})
        return decision.protocol == "broadcast" and policy.get("broadcast") == "log"


class RateLimiter:
    def __init__(self, maximum, window=1.0):
        self.maximum = int(maximum)
        self.window = float(window)
        self.events = defaultdict(deque)

    def allow(self, key, now=None):
        now = time.monotonic() if now is None else now
        history = self.events[key]
        while history and now - history[0] >= self.window:
            history.popleft()
        if len(history) >= self.maximum:
            return False
        history.append(now)
        return True


class DuplicateFilter:
    def __init__(self, ttl=1.0, maximum=2048):
        self.ttl = float(ttl)
        self.maximum = int(maximum)
        self.seen = {}

    def is_duplicate(self, frame, now=None):
        now = time.monotonic() if now is None else now
        fingerprint = hashlib.sha256(frame).digest()
        previous = self.seen.get(fingerprint)
        self.seen[fingerprint] = now
        if len(self.seen) > self.maximum:
            cutoff = now - self.ttl
            self.seen = {
                key: timestamp
                for key, timestamp in self.seen.items()
                if timestamp >= cutoff
            }
        return previous is not None and now - previous < self.ttl


class DiscoveryRelay:
    def __init__(
        self,
        interface,
        policy_store,
        rate_limit=20,
        socket_factory=socket.socket,
    ):
        if not INTERFACE_PATTERN.fullmatch(interface):
            raise ValueError("nombre de interfaz no valido")
        self.interface = interface
        self.policy_store = policy_store
        self.rate_limiter = RateLimiter(rate_limit)
        self.duplicates = DuplicateFilter()
        self.socket_factory = socket_factory
        self.running = True
        self.forwarded = defaultdict(int)
        self.blocked = defaultdict(int)

    def process_frame(self, frame, packet_type=0, now=None):
        if packet_type == PACKET_OUTGOING:
            return False
        decision = classify_frame(frame)
        if decision is None:
            return False
        self.policy_store.refresh(now=now)
        if not self.policy_store.decision_allowed(decision):
            self.blocked[decision.protocol] += 1
            return False
        if self.duplicates.is_duplicate(frame, now=now):
            return False
        if not self.rate_limiter.allow(
            (decision.source_mac, decision.protocol), now=now
        ):
            self.blocked[f"{decision.protocol}_rate"] += 1
            return False
        self.forwarded[decision.protocol] += 1
        if self.policy_store.should_log_broadcast(decision):
            print(
                f"Broadcast autorizado y registrado para {decision.source_mac}",
                flush=True,
            )
        return True

    def stop(self, *_args):
        self.running = False

    def run(self):
        self.policy_store.refresh(force=True)
        packet_socket = self.socket_factory(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        packet_socket.bind((self.interface, 0))
        packet_socket.settimeout(1.0)
        print(
            f"Relay de descubrimiento activo en {self.interface}; "
            "permisos por dispositivo emisor.",
            flush=True,
        )
        last_summary = time.monotonic()
        while self.running:
            try:
                frame, address = packet_socket.recvfrom(65535)
            except socket.timeout:
                frame = None
                address = None
            if frame is not None:
                packet_type = address[2] if len(address) > 2 else 0
                if self.process_frame(frame, packet_type=packet_type):
                    packet_socket.send(frame)
            now = time.monotonic()
            if now - last_summary >= 60:
                print(
                    "Resumen relay: "
                    f"reenviados={dict(self.forwarded)} "
                    f"bloqueados={dict(self.blocked)}",
                    flush=True,
                )
                last_summary = now
        packet_socket.close()


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--policies", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument(
        "--reload-interval", type=float, default=DEFAULT_RELOAD_INTERVAL
    )
    parser.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.reload_interval <= 0 or args.rate_limit <= 0:
        raise SystemExit("reload-interval y rate-limit deben ser positivos")
    store = PolicyStore(args.policies, args.database, args.reload_interval)
    relay = DiscoveryRelay(args.interface, store, args.rate_limit)
    signal.signal(signal.SIGTERM, relay.stop)
    signal.signal(signal.SIGINT, relay.stop)
    relay.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
