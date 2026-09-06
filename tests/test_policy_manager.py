import copy
import json
import subprocess
from unittest.mock import patch

import pytest

import policy_manager


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=stdout,
        stderr=stderr,
    )


def make_manager(tmp_path, document=None):
    path = tmp_path / "policies.json"
    if document is not None:
        path.write_text(json.dumps(document), encoding="utf-8")
    return policy_manager.PolicyManager(str(path))


def active_device(policy=None):
    return {
        "02:00:00:00:00:01": {
            "client_ip": "192.168.10.100",
            "gateway_ip": "192.168.10.1",
            "subnet": "192.168.10.0/24",
            "policy": dict(policy_manager.DEFAULT_POLICY if policy is None else policy),
        }
    }


def test_base_rules_are_static_and_fail_closed():
    ruleset = policy_manager.render_base_ruleset()

    assert "set client_macs { type ether_addr;" in ruleset
    assert "ether saddr != @client_macs counter drop" in ruleset
    assert "ip daddr 224.0.0.251 udp dport 5353 counter accept" in ruleset
    assert "ip daddr 239.255.255.250 udp dport 1900 counter accept" in ruleset
    assert "ether type ip6 counter drop" in ruleset
    assert "ip saddr != @peer_allowed_ips counter drop" in ruleset
    assert "meta mark set 0x100" in ruleset
    assert (
        'ip saddr @internet_blocked_ips oifname "eth0" counter drop'
        in ruleset
    )
    assert "internet_blocked_ips ip daddr != @device_subnets" not in ruleset


def test_internet_policy_can_target_a_different_wan_interface():
    ruleset = policy_manager.render_base_ruleset(wan_interface="wan0")

    assert (
        'ip saddr @internet_blocked_ips oifname "wan0" counter drop'
        in ruleset
    )


def test_manager_installs_base_rules_on_configured_ap_interface(tmp_path):
    manager = policy_manager.PolicyManager(
        str(tmp_path / "policies.json"),
        interface="phy4-ap0",
    )
    calls = []

    def fake_run(command, input_text=None, allow_fail=False):
        calls.append((command, input_text))
        return completed(command)

    with patch.object(manager, "_run_nft", side_effect=fake_run):
        assert manager._install_base_locked() is True

    rulesets = [
        input_text
        for command, input_text in calls
        if command == ["nft", "-f", "-"] and input_text
    ]
    assert any('device "phy4-ap0"' in ruleset for ruleset in rulesets)


def test_register_transaction_adds_only_dynamic_set_elements():
    transaction = policy_manager.render_set_update({}, active_device())

    assert policy_manager.DEFAULT_POLICY["mdns"] is False
    assert policy_manager.DEFAULT_POLICY["ssdp"] is False
    assert "add element netdev tfg_l2 client_macs" in transaction
    assert "02:00:00:00:00:01 . 192.168.10.100" in transaction
    assert "mdns_allowed_macs" not in transaction
    assert "ssdp_allowed_macs" not in transaction
    assert "add element inet tfg_l3 device_subnets { 192.168.10.0/24 }" in transaction
    assert "internet_blocked_ips" not in transaction
    assert "peer_allowed_ips" not in transaction
    assert "table netdev" not in transaction


def test_policy_change_updates_only_affected_sets():
    previous_policy = dict(policy_manager.DEFAULT_POLICY)
    previous_policy["ssdp"] = True
    previous = active_device(previous_policy)
    changed_policy = dict(previous_policy)
    changed_policy.update({"internet": False, "inter_device": True, "ssdp": False})
    desired = active_device(changed_policy)

    transaction = policy_manager.render_set_update(previous, desired)

    assert "add element inet tfg_l3 internet_blocked_ips" in transaction
    assert "add element inet tfg_l3 peer_allowed_ips" in transaction
    assert "add element netdev tfg_l2 peer_allowed_macs" in transaction
    assert "delete element netdev tfg_l2 ssdp_allowed_macs" in transaction
    assert "client_macs" not in transaction


def test_reconcile_devices_restores_all_runtime_assignments(tmp_path):
    manager = make_manager(tmp_path)
    devices = {
        "02:00:00:00:00:01": {
            "client_ip": "192.168.10.100",
            "gateway_ip": "192.168.10.1",
        },
        "02:00:00:00:00:02": {
            "client_ip": "192.168.11.100",
            "gateway_ip": "192.168.11.1",
        },
    }

    with patch.object(
        manager, "_install_base_locked", return_value=True
    ) as install:
        assert manager.reconcile_devices(devices) is True

    assert set(manager._active) == set(devices)
    assert (
        manager._active["02:00:00:00:00:01"]["subnet"]
        == "192.168.10.0/24"
    )
    assert (
        manager._active["02:00:00:00:00:02"]["subnet"]
        == "192.168.11.0/24"
    )
    install.assert_called_once_with()


def test_failed_reconcile_keeps_previous_internal_state(tmp_path):
    manager = make_manager(tmp_path)
    manager._active = active_device()
    previous = copy.deepcopy(manager._active)

    with patch.object(manager, "_install_base_locked", return_value=False):
        result = manager.reconcile_devices(
            {
                "02:00:00:00:00:02": {
                    "client_ip": "192.168.11.100",
                    "gateway_ip": "192.168.11.1",
                }
            }
        )

    assert result is False
    assert manager._active == previous


def test_runtime_client_macs_are_read_from_the_active_nft_set(tmp_path):
    manager = make_manager(tmp_path)
    output = """table netdev tfg_l2 {
        set client_macs {
            type ether_addr
            elements = { 02:00:00:00:00:01, AA:BB:CC:DD:EE:FF }
        }
    }"""
    with patch.object(
        manager,
        "_run_nft",
        return_value=completed([], stdout=output),
    ):
        clients = manager.runtime_client_macs()

    assert clients == {"02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff"}


def test_policy_file_merges_device_overrides_with_defaults(tmp_path):
    manager = make_manager(
        tmp_path,
        {
            "default": {"mdns": False, "ssdp": True},
            "devices": {
                "02:00:00:00:00:01": {"ssdp": False, "internet": False}
            },
        },
    )

    assert manager.get_policy("02:00:00:00:00:01") == {
        "internet": False,
        "inter_device": False,
        "mdns": False,
        "ssdp": False,
        "broadcast": "block",
    }


def test_register_uses_nft_only_and_never_reloads_firewall(tmp_path):
    manager = make_manager(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        return completed(command)

    with patch.object(policy_manager.subprocess, "run", side_effect=fake_run):
        assert manager.register_device(
            "02:00:00:00:00:01", "192.168.10.100", "192.168.10.1"
        ) is True

    commands = [command for command, _ in calls]
    assert all(command[0] == "nft" for command in commands)
    assert ["/etc/init.d/firewall", "reload"] not in commands
    transactions = [rules for _, rules in calls if rules]
    assert any("add element netdev tfg_l2 client_macs" in rules for rules in transactions)


def test_failed_atomic_update_keeps_previous_active_state(tmp_path):
    manager = make_manager(tmp_path)

    def fake_run(command, **kwargs):
        ruleset = kwargs.get("input") or ""
        if "add element" in ruleset:
            return completed(command, returncode=1, stderr="set update failed")
        return completed(command)

    with patch.object(policy_manager.subprocess, "run", side_effect=fake_run):
        assert manager.register_device(
            "02:00:00:00:00:01", "192.168.10.100", "192.168.10.1"
        ) is False

    assert manager._active == {}


def test_missing_tables_are_recreated_before_set_update(tmp_path):
    manager = make_manager(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs.get("input") or ""))
        if command[:3] == ["nft", "list", "table"]:
            return completed(command, returncode=1, stderr="not found")
        return completed(command)

    with patch.object(policy_manager.subprocess, "run", side_effect=fake_run):
        assert manager.register_device(
            "02:00:00:00:00:01", "192.168.10.100", "192.168.10.1"
        ) is True

    assert any("table netdev tfg_l2" in rules for _, rules in calls)
    assert all(command[0] == "nft" for command, _ in calls)


def test_update_policy_is_persisted_atomically_for_inactive_device(tmp_path):
    manager = make_manager(tmp_path)

    assert manager.update_policy(
        "02:00:00:00:00:01",
        internet=False,
        ssdp=False,
        broadcast="log",
    ) is True

    saved = json.loads((tmp_path / "policies.json").read_text(encoding="utf-8"))
    assert saved["devices"]["02:00:00:00:00:01"]["internet"] is False
    assert saved["devices"]["02:00:00:00:00:01"]["ssdp"] is False
    assert saved["devices"]["02:00:00:00:00:01"]["broadcast"] == "log"


def test_reset_policy_removes_override_and_applies_default_to_active_device(tmp_path):
    mac = "02:00:00:00:00:01"
    trusted = dict(policy_manager.DEFAULT_POLICY)
    trusted.update(
        {"inter_device": True, "mdns": True, "ssdp": True, "broadcast": "allow"}
    )
    manager = make_manager(
        tmp_path,
        {"default": policy_manager.DEFAULT_POLICY, "devices": {mac: trusted}},
    )
    manager._active = active_device(trusted)

    with patch.object(
        manager, "_run_nft", return_value=completed([])
    ) as run_nft:
        assert manager.reset_policy(mac) is True

    saved = json.loads((tmp_path / "policies.json").read_text(encoding="utf-8"))
    assert mac not in saved["devices"]
    assert manager._active[mac]["policy"] == policy_manager.DEFAULT_POLICY
    transaction = run_nft.call_args.args[1]
    assert "delete element netdev tfg_l2 mdns_allowed_macs" in transaction
    assert "delete element netdev tfg_l2 ssdp_allowed_macs" in transaction
    assert "delete element inet tfg_l3 peer_allowed_ips" in transaction


def test_invalid_policy_value_is_rejected_without_writing(tmp_path):
    manager = make_manager(tmp_path)

    assert manager.update_policy(
        "02:00:00:00:00:01", broadcast="sometimes"
    ) is False
    assert not (tmp_path / "policies.json").exists()


def test_management_ip_rules_precede_unknown_client_drop(tmp_path):
    manager = make_manager(
        tmp_path,
        {
            "management_ip": "192.168.50.20",
            "management_router_ip": "192.168.50.1",
        },
    )

    ruleset = policy_manager.render_base_ruleset(
        management_ip=manager._document["management_ip"],
        management_router_ip=manager._document["management_router_ip"],
    )

    assert "arp saddr ip 192.168.50.20 arp daddr ip 192.168.50.1" in ruleset
    assert "ether type ip ip saddr 192.168.50.20 counter accept" in ruleset
    assert "ip saddr 192.168.50.20 ip daddr 192.168.50.1" not in ruleset
    assert ruleset.index("ip saddr 192.168.50.20") < ruleset.index("ether saddr != @client_macs")


def test_reload_updates_active_and_future_devices_without_rewriting_file(tmp_path):
    manager = make_manager(tmp_path, {})
    previous_policy = dict(policy_manager.DEFAULT_POLICY)
    previous_policy["mdns"] = True
    manager._active = active_device(previous_policy)
    mac = "02:00:00:00:00:01"
    path = tmp_path / "policies.json"
    contents = json.dumps({
        "default": {"internet": False},
        "devices": {mac: {"mdns": False, "broadcast": "allow"}},
    })
    path.write_text(contents, encoding="utf-8")

    with patch.object(
        policy_manager.subprocess, "run", return_value=completed([])
    ) as run:
        assert manager.reload_policies() is True
        run.assert_called_once()
        assert run.call_args.args[0] == ["nft", "-f", "-"]
        transaction = run.call_args.kwargs["input"]
        assert "add element inet tfg_l3 internet_blocked_ips" in transaction
        assert "delete element netdev tfg_l2 mdns_allowed_macs" in transaction
        assert "add element netdev tfg_l2 broadcast_allowed_macs" in transaction
        assert manager._active[mac]["policy"] == manager.get_policy(mac)
        assert manager.get_policy("02:00:00:00:00:02")["internet"] is False
        run.reset_mock()
        assert manager.reload_policies() is True
        run.assert_not_called()

    assert path.read_text(encoding="utf-8") == contents


def test_reload_removed_override_restores_default(tmp_path):
    mac = "02:00:00:00:00:01"
    manager = make_manager(tmp_path, {
        "default": {"internet": False},
        "devices": {mac: {"internet": True}},
    })
    manager._active = active_device(manager.get_policy(mac))
    (tmp_path / "policies.json").write_text(
        json.dumps({"default": {"internet": False}}), encoding="utf-8"
    )

    with patch.object(
        policy_manager.subprocess, "run", return_value=completed([])
    ) as run:
        assert manager.reload_policies() is True

    assert manager._active[mac]["policy"]["internet"] is False
    assert "internet_blocked_ips" in run.call_args.kwargs["input"]


@pytest.mark.parametrize("contents", [
    b'{"default":',
    b'[]',
    b'{"default": null}',
    b'{"default": {"internet": "false"}}',
    b'{"default": {"broadcast": []}}',
    b'{"devices": []}',
    b'{"devices": {"bad-mac": {}}}',
    b'{"devices": {"02:00:00:00:00:02": null}}',
    b'{"devices": {"02:00:00:00:00:02": {"unknown": true}}}',
    b'\xff',
])
def test_invalid_reload_preserves_all_policies(tmp_path, contents):
    manager = make_manager(tmp_path, {"default": {"internet": False}})
    manager._active = active_device(manager.get_policy("02:00:00:00:00:01"))
    previous_document = copy.deepcopy(manager._document)
    previous_active = copy.deepcopy(manager._active)
    (tmp_path / "policies.json").write_bytes(contents)

    with patch.object(policy_manager.subprocess, "run") as run:
        assert manager.reload_policies() is False
        run.assert_not_called()

    assert manager._document == previous_document
    assert manager._active == previous_active


def test_missing_file_keeps_last_policy_and_recovers_when_restored(tmp_path, capsys):
    manager = make_manager(tmp_path, {"default": {"internet": False}})
    path = tmp_path / "policies.json"
    path.unlink()

    with patch.object(policy_manager.subprocess, "run") as run:
        assert manager.reload_policies() is False
        assert manager.reload_policies() is False
        assert manager.get_policy("02:00:00:00:00:01")["internet"] is False
        assert capsys.readouterr().out.count("Recarga rechazada") == 1
        path.write_text(json.dumps({"default": {"internet": True}}), encoding="utf-8")
        assert manager.reload_policies() is True
        assert manager.get_policy("02:00:00:00:00:01")["internet"] is True
        run.assert_not_called()


def test_failed_reload_is_atomic_for_all_devices_and_retried(tmp_path):
    manager = make_manager(tmp_path, {})
    manager._active = active_device()
    second = copy.deepcopy(next(iter(manager._active.values())))
    second.update(client_ip="192.168.11.100", gateway_ip="192.168.11.1",
                  subnet="192.168.11.0/24")
    manager._active["02:00:00:00:00:02"] = second
    previous_document = copy.deepcopy(manager._document)
    previous_active = copy.deepcopy(manager._active)
    (tmp_path / "policies.json").write_text(
        json.dumps({"default": {"internet": False}}), encoding="utf-8"
    )

    with patch.object(policy_manager.subprocess, "run", side_effect=[
        completed([], returncode=1, stderr="fallo simulado"), completed([]),
    ]) as run:
        assert manager.reload_policies() is False
        assert manager._document == previous_document
        assert manager._active == previous_active
        assert manager.reload_policies() is True

    assert run.call_count == 2
    assert run.call_args_list[0] == run.call_args_list[1]
    transaction = run.call_args.kwargs["input"]
    assert "192.168.10.100" in transaction
    assert "192.168.11.100" in transaction
    assert all(not device["policy"]["internet"] for device in manager._active.values())


def test_reload_rejects_management_changes_without_applying_permissions(tmp_path):
    manager = make_manager(tmp_path, {})
    previous = copy.deepcopy(manager._document)
    (tmp_path / "policies.json").write_text(json.dumps({
        "default": {"internet": False},
        "management_ip": "192.168.50.20",
        "management_router_ip": "192.168.50.1",
    }), encoding="utf-8")

    with patch.object(policy_manager.subprocess, "run") as run:
        assert manager.reload_policies() is False
        run.assert_not_called()
    assert manager._document == previous


def test_forget_devices_removes_only_requested_overrides(tmp_path):
    first = "02:00:00:00:00:01"
    second = "02:00:00:00:00:02"
    manager = make_manager(
        tmp_path,
        {
            "devices": {
                first: {"mdns": True},
                second: {"ssdp": True},
            }
        },
    )

    assert manager.forget_devices([first]) is True

    saved = json.loads(
        (tmp_path / "policies.json").read_text(encoding="utf-8")
    )
    assert first not in saved["devices"]
    assert second in saved["devices"]


def test_forget_devices_refuses_an_active_device(tmp_path):
    mac = "02:00:00:00:00:01"
    manager = make_manager(
        tmp_path,
        {"devices": {mac: {"mdns": True}}},
    )
    manager._active = active_device()

    assert manager.forget_devices([mac]) is False
    saved = json.loads(
        (tmp_path / "policies.json").read_text(encoding="utf-8")
    )
    assert mac in saved["devices"]
