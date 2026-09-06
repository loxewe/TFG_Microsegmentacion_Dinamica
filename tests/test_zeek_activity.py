from zeek_activity import (
    empty_activity,
    format_byte_count,
    load_device_activity,
    read_zeek_records,
)


CONN_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tcount\tcount
"""

DNS_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery
#types\ttime\tstring\taddr\taddr\tstring
"""


def test_read_zeek_records_parses_header_and_tail_limit(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        CONN_HEADER
        + "100.0\tC1\t192.168.10.100\t1234\t203.0.113.1\t443\ttcp\tssl\t10\t20\n"
        + "101.0\tC2\t192.168.10.100\t1235\t203.0.113.2\t53\tudp\tdns\t30\t40\n",
        encoding="utf-8",
    )

    records = read_zeek_records(path, max_records=1)

    assert records == [
        {
            "ts": "101.0",
            "uid": "C2",
            "id.orig_h": "192.168.10.100",
            "id.orig_p": "1235",
            "id.resp_h": "203.0.113.2",
            "id.resp_p": "53",
            "proto": "udp",
            "service": "dns",
            "orig_bytes": "30",
            "resp_bytes": "40",
        }
    ]


def test_activity_maps_conn_and_dns_to_inventory(tmp_path):
    (tmp_path / "conn.log").write_text(
        CONN_HEADER
        + "100.0\tC1\t192.168.10.100\t1234\t203.0.113.1\t443\ttcp\tssl\t100\t250\n"
        + "110.0\tC2\t198.51.100.4\t4321\t192.168.10.100\t22\ttcp\tssh\t40\t20\n"
        + "115.0\tC3\t192.168.99.100\t1234\t203.0.113.8\t443\ttcp\tssl\t999\t999\n",
        encoding="utf-8",
    )
    (tmp_path / "dns.log").write_text(
        DNS_HEADER
        + "120.0\tD1\t192.168.10.100\t8.8.8.8\texample.test\n"
        + "121.0\tD2\t192.168.99.100\t8.8.8.8\tignored.test\n",
        encoding="utf-8",
    )
    devices = [
        {
            "mac": "02:00:00:00:00:01",
            "ip": "192.168.10.100",
        },
        {
            "mac": "02:00:00:00:00:02",
            "ip": "192.168.15.100",
        },
    ]

    activity = load_device_activity(devices, tmp_path, now=130.0)

    first = activity["02:00:00:00:00:01"]
    assert first["connections"] == 2
    assert first["bytes_sent"] == 120
    assert first["bytes_received"] == 290
    assert first["destinations"] == ["203.0.113.1", "198.51.100.4"]
    assert first["protocols"] == ["ssl", "ssh"]
    assert first["dns_queries"] == ["example.test"]
    assert first["external_attempts"] == 1
    assert first["peer_flows"] == 0
    assert first["source_status"] == "available"
    assert first["source_error"] is None
    assert first["last_seen"] == "1970-01-01 00:02:00 UTC"
    assert first["recent"] is True
    inactive = empty_activity()
    inactive["source_status"] = "available"
    assert activity["02:00:00:00:00:02"] == inactive


def test_missing_logs_are_safe_and_byte_counts_are_readable(tmp_path):
    devices = [{"mac": "02:00:00:00:00:01", "ip": "192.168.10.100"}]

    activity = load_device_activity(devices, tmp_path)[
        "02:00:00:00:00:01"
    ]
    assert activity["source_status"] == "unavailable"
    assert activity["source_error"]
    activity["source_error"] = None
    assert activity == empty_activity()
    assert format_byte_count(0) == "0 B"
    assert format_byte_count(1536) == "1.5 KB"


def test_activity_distinguishes_partial_and_invalid_zeek_sources(tmp_path):
    (tmp_path / "conn.log").write_text(CONN_HEADER, encoding="utf-8")
    devices = [{"mac": "02:00:00:00:00:01", "ip": "192.168.10.100"}]

    activity = load_device_activity(devices, tmp_path)

    assert activity["02:00:00:00:00:01"]["source_status"] == "partial"
    assert activity["02:00:00:00:00:01"]["source_error"]

    (tmp_path / "conn.log").write_text("not a Zeek log\n", encoding="utf-8")
    activity = load_device_activity(devices, tmp_path)

    assert activity["02:00:00:00:00:01"]["source_status"] == "unavailable"
    assert "formato Zeek no reconocido" in (
        activity["02:00:00:00:00:01"]["source_error"]
    )


def test_policy_related_traffic_is_classified_without_claiming_enforcement(
    tmp_path,
):
    (tmp_path / "conn.log").write_text(
        CONN_HEADER
        + "200.0\tC1\t192.168.10.100\t1000\t192.168.15.100\t443\ttcp\tssl\t1\t1\n"
        + "201.0\tC2\t192.168.10.100\t5353\t224.0.0.251\t5353\tudp\tdns\t1\t1\n"
        + "202.0\tC3\t192.168.10.100\t1900\t239.255.255.250\t1900\tudp\t-\t1\t1\n"
        + "203.0\tC4\t192.168.10.100\t1001\t192.168.10.255\t9999\tudp\t-\t1\t1\n"
        + "204.0\tC5\t192.168.10.100\t1002\t203.0.113.9\t443\ttcp\tssl\t1\t1\n",
        encoding="utf-8",
    )
    devices = [
        {
            "mac": "02:00:00:00:00:01",
            "ip": "192.168.10.100",
            "gateway": "192.168.10.1",
        },
        {
            "mac": "02:00:00:00:00:02",
            "ip": "192.168.15.100",
            "gateway": "192.168.15.1",
        },
    ]

    activity = load_device_activity(devices, tmp_path, now=205.0)

    first = activity["02:00:00:00:00:01"]
    second = activity["02:00:00:00:00:02"]
    assert first["external_attempts"] == 1
    assert first["peer_flows"] == 1
    assert first["mdns_events"] == 1
    assert first["ssdp_events"] == 1
    assert first["broadcast_events"] == 1
    assert second["peer_flows"] == 1


def test_mdns_and_ssdp_require_udp_transport(tmp_path):
    (tmp_path / "conn.log").write_text(
        CONN_HEADER
        + "200.0\tC1\t192.168.10.100\t1000\t224.0.0.251\t5353\ttcp\t-\t1\t1\n"
        + "201.0\tC2\t192.168.10.100\t1001\t239.255.255.250\t1900\ttcp\t-\t1\t1\n",
        encoding="utf-8",
    )
    devices = [
        {
            "mac": "02:00:00:00:00:01",
            "ip": "192.168.10.100",
            "gateway": "192.168.10.1",
        }
    ]

    activity = load_device_activity(devices, tmp_path, now=205.0)[
        "02:00:00:00:00:01"
    ]

    assert activity["mdns_events"] == 0
    assert activity["ssdp_events"] == 0
