import json
import subprocess

from policy_observer import (
    TABLE_SPECS,
    load_policy_application,
    read_policy_snapshot,
)


MAC = "02:00:00:00:00:01"
IP = "192.168.10.100"


def nft_document(specification, elements=None, separate_elements=False):
    elements = elements or {}
    entries = [
        {
            "table": {
                "family": specification["family"],
                "name": specification["table"],
            }
        }
    ]
    for name in specification["sets"]:
        entries.append(
            {
                "set": {
                    "family": specification["family"],
                    "table": specification["table"],
                    "name": name,
                    "elem": [] if separate_elements else elements.get(name, []),
                }
            }
        )
        if separate_elements and elements.get(name):
            entries.append(
                {
                    "element": {
                        "family": specification["family"],
                        "table": specification["table"],
                        "name": name,
                        "elem": [{"val": value} for value in elements[name]],
                    }
                }
            )
    return json.dumps({"nftables": entries})


def fake_nft(l2_elements=None, l3_elements=None, separate_elements=False):
    documents = {
        "tfg_l2": nft_document(
            TABLE_SPECS["l2"], l2_elements, separate_elements
        ),
        "tfg_l3": nft_document(
            TABLE_SPECS["l3"], l3_elements, separate_elements
        ),
    }

    def run(command, **kwargs):
        assert command[:4] == ["nft", "-j", "list", "table"]
        assert kwargs["timeout"] == 3
        return subprocess.CompletedProcess(command, 0, documents[command[-1]], "")

    return run


def device(created=True):
    return {
        "mac": MAC,
        "ip": IP,
        "created": created,
        "policy": {
            "internet": False,
            "inter_device": True,
            "mdns": True,
            "ssdp": False,
            "broadcast": "log",
        },
    }


def test_effective_sets_match_configured_policy():
    run = fake_nft(
        l2_elements={
            "peer_allowed_macs": [MAC],
            "mdns_allowed_macs": [MAC],
            "discovery_allowed_macs": [MAC],
            "broadcast_logged_macs": [MAC],
        },
        l3_elements={
            "internet_blocked_ips": [IP],
            "peer_allowed_ips": [IP],
        },
        separate_elements=True,
    )

    result = load_policy_application([device()], run=run)[MAC]

    assert result["status"] == "applied"
    assert result["differences"] == []
    assert result["controls"]["internet"]["effective"] is False
    assert result["controls"]["broadcast"]["effective"] == "log"


def test_different_sets_identify_each_mismatched_control():
    result = load_policy_application(
        [device()], run=fake_nft()
    )[MAC]

    assert result["status"] == "different"
    assert result["differences"] == [
        "internet",
        "inter_device",
        "mdns",
        "discovery",
        "broadcast",
    ]
    assert result["controls"]["ssdp"]["status"] == "applied"


def test_nft_failure_returns_unavailable_without_guessing_effective_state():
    def failed(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "not found")

    result = load_policy_application([device()], run=failed)[MAC]

    assert result["status"] == "unavailable"
    assert result["controls"]["internet"]["effective"] is None
    assert "nft devolvió 1" in result["error"]


def test_plain_nft_output_is_used_when_json_is_not_available():
    def plain_table(specification, elements):
        lines = [
            f"table {specification['family']} {specification['table']} {{"
        ]
        for name in specification["sets"]:
            values = ", ".join(elements.get(name, []))
            lines.extend(
                [
                    f"    set {name} {{",
                    "        type ipv4_addr",
                    f"        elements = {{ {values} }}" if values else "",
                    "    }",
                ]
            )
        lines.append("}")
        return "\n".join(lines)

    documents = {
        "tfg_l2": plain_table(
            TABLE_SPECS["l2"], {"broadcast_logged_macs": [MAC]}
        ),
        "tfg_l3": plain_table(
            TABLE_SPECS["l3"], {"internet_blocked_ips": [IP]}
        ),
    }

    def run(command, **kwargs):
        if "-j" in command:
            return subprocess.CompletedProcess(command, 1, "", "unsupported")
        return subprocess.CompletedProcess(command, 0, documents[command[-1]], "")

    configured = device()
    configured["policy"]["inter_device"] = False
    configured["policy"]["mdns"] = False
    result = load_policy_application([configured], run=run)[MAC]

    assert result["status"] == "applied"


def test_inactive_devices_do_not_query_nftables():
    def unexpected(*args, **kwargs):
        raise AssertionError("nft must not be queried for inactive devices")

    result = load_policy_application(
        [device(created=False)], run=unexpected
    )[MAC]

    assert result["status"] == "inactive"
    assert result["controls"]["internet"]["status"] == "inactive"
    assert result["controls"]["discovery"] == {
        "configured": True,
        "effective": None,
        "status": "inactive",
    }


def test_inconsistent_peer_sets_are_reported_as_different():
    run = fake_nft(l2_elements={"peer_allowed_macs": [MAC]})
    configured = device()
    configured["policy"]["inter_device"] = False

    result = load_policy_application([configured], run=run)[MAC]

    assert result["controls"]["inter_device"] == {
        "configured": False,
        "effective": None,
        "status": "different",
    }
    assert "inter_device" in result["differences"]


def test_missing_required_set_marks_snapshot_unavailable():
    document = json.loads(nft_document(TABLE_SPECS["l2"]))
    document["nftables"] = [
        entry
        for entry in document["nftables"]
        if entry.get("set", {}).get("name") != "mdns_allowed_macs"
    ]

    def run(command, **kwargs):
        if command[-1] == "tfg_l2":
            output = json.dumps(document)
        else:
            output = nft_document(TABLE_SPECS["l3"])
        return subprocess.CompletedProcess(command, 0, output, "")

    snapshot = read_policy_snapshot(run=run)

    assert snapshot["available"] is False
    assert snapshot["tables"] == {"l2": False, "l3": True}
    assert "mdns_allowed_macs" in snapshot["error"]
