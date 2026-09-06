import json
import socket
import struct

from discovery_relay import (
    BROADCAST_MAC,
    PACKET_OUTGOING,
    DiscoveryRelay,
    PolicyStore,
    classify_frame,
)


SOURCE_MAC = "02:00:00:00:00:01"
SOURCE_BYTES = bytes.fromhex(SOURCE_MAC.replace(":", ""))


def udp_frame(destination_mac, destination_ip, source_port=12345, destination_port=9):
    payload = b"test"
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp) + len(payload),
        1,
        0,
        1,
        socket.IPPROTO_UDP,
        0,
        socket.inet_aton("192.0.2.10"),
        socket.inet_aton(destination_ip),
    )
    return destination_mac + SOURCE_BYTES + struct.pack("!H", 0x0800) + ip + udp + payload


def test_classifies_exact_mdns_ssdp_and_ipv4_broadcast():
    mdns = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", destination_port=5353)
    ssdp = udp_frame(bytes.fromhex("01005e7ffffa"), "239.255.255.250", destination_port=1900)
    broadcast = udp_frame(BROADCAST_MAC, "192.0.2.255")

    assert classify_frame(mdns).protocol == "mdns"
    assert classify_frame(ssdp).protocol == "ssdp"
    assert classify_frame(broadcast).protocol == "broadcast"
    assert classify_frame(mdns).source_mac == SOURCE_MAC


def test_rejects_dhcp_ipv6_arp_and_unrelated_multicast():
    dhcp = udp_frame(BROADCAST_MAC, "255.255.255.255", 68, 67)
    ipv6 = BROADCAST_MAC + SOURCE_BYTES + struct.pack("!H", 0x86DD) + bytes(40)
    arp = BROADCAST_MAC + SOURCE_BYTES + struct.pack("!H", 0x0806) + bytes(28)
    unrelated = udp_frame(bytes.fromhex("01005e000001"), "224.0.0.1", destination_port=9999)

    assert classify_frame(dhcp) is None
    assert classify_frame(ipv6) is None
    assert classify_frame(arp) is None
    assert classify_frame(unrelated) is None


def test_rejects_multicast_ip_sent_to_an_unexpected_ethernet_destination():
    forged = udp_frame(
        bytes.fromhex("020000000099"),
        "224.0.0.251",
        destination_port=5353,
    )

    assert classify_frame(forged) is None


def test_policy_store_merges_defaults_and_only_keeps_active_devices(tmp_path):
    policies = tmp_path / "policies.json"
    database = tmp_path / "database.json"
    policies.write_text(
        json.dumps(
            {
                "default": {"mdns": False, "ssdp": True, "broadcast": "block"},
                "devices": {SOURCE_MAC: {"mdns": True, "broadcast": "log"}},
            }
        ),
        encoding="utf-8",
    )
    database.write_text(
        json.dumps(
            {
                SOURCE_MAC: {"creada": True, "ip_cliente": "192.0.2.10"},
                "02:00:00:00:00:02": {
                    "creada": False,
                    "ip_cliente": "192.0.2.11",
                },
            }
        ),
        encoding="utf-8",
    )

    store = PolicyStore(policies, database)
    assert store.refresh(force=True)
    assert store.permissions == {
        SOURCE_MAC: {
            "client_ip": "192.0.2.10",
            "mdns": True,
            "ssdp": True,
            "broadcast": "log",
        }
    }


def test_invalid_or_missing_policy_fails_closed(tmp_path):
    policies = tmp_path / "policies.json"
    database = tmp_path / "database.json"
    policies.write_text("not-json", encoding="utf-8")
    database.write_text(
        json.dumps({SOURCE_MAC: {"creada": True, "ip_cliente": "192.0.2.10"}}),
        encoding="utf-8",
    )
    store = PolicyStore(policies, database)
    store.permissions = {SOURCE_MAC: {"mdns": True}}

    store.refresh(force=True)

    assert store.permissions == {}
    assert store.last_error


def test_relay_applies_emitter_policy_and_skips_outgoing_and_duplicates(tmp_path):
    policies = tmp_path / "policies.json"
    database = tmp_path / "database.json"
    policies.write_text(
        json.dumps({"default": {}, "devices": {SOURCE_MAC: {"mdns": True}}}),
        encoding="utf-8",
    )
    database.write_text(
        json.dumps({SOURCE_MAC: {"creada": True, "ip_cliente": "192.0.2.10"}}),
        encoding="utf-8",
    )
    store = PolicyStore(policies, database, reload_interval=2)
    store.refresh(force=True)
    relay = DiscoveryRelay("phy0-ap0", store)
    mdns = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", destination_port=5353)
    ssdp = udp_frame(bytes.fromhex("01005e7ffffa"), "239.255.255.250", destination_port=1900)

    assert relay.process_frame(mdns, now=10) is True
    assert relay.process_frame(mdns, now=10.1) is False
    assert relay.process_frame(mdns, packet_type=PACKET_OUTGOING, now=12) is False
    assert relay.process_frame(ssdp, now=12) is False


def test_relay_rejects_a_permitted_mac_with_the_wrong_source_ip(tmp_path):
    policies = tmp_path / "policies.json"
    database = tmp_path / "database.json"
    policies.write_text(
        json.dumps({"default": {"mdns": True}, "devices": {}}), encoding="utf-8"
    )
    database.write_text(
        json.dumps({SOURCE_MAC: {"creada": True, "ip_cliente": "192.0.2.99"}}),
        encoding="utf-8",
    )
    store = PolicyStore(policies, database)
    store.refresh(force=True)
    relay = DiscoveryRelay("phy0-ap0", store)
    mdns = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", destination_port=5353)

    assert relay.process_frame(mdns, now=10) is False


def test_rate_limit_blocks_excess_per_device_and_protocol(tmp_path):
    policies = tmp_path / "policies.json"
    database = tmp_path / "database.json"
    policies.write_text(
        json.dumps({"default": {"mdns": True}, "devices": {}}), encoding="utf-8"
    )
    database.write_text(
        json.dumps({SOURCE_MAC: {"creada": True, "ip_cliente": "192.0.2.10"}}),
        encoding="utf-8",
    )
    store = PolicyStore(policies, database)
    store.refresh(force=True)
    relay = DiscoveryRelay("phy0-ap0", store, rate_limit=2)

    first = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", 1001, 5353)
    second = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", 1002, 5353)
    third = udp_frame(bytes.fromhex("01005e0000fb"), "224.0.0.251", 1003, 5353)
    assert relay.process_frame(first, now=20) is True
    assert relay.process_frame(second, now=20.1) is True
    assert relay.process_frame(third, now=20.2) is False
    assert relay.blocked["mdns_rate"] == 1
