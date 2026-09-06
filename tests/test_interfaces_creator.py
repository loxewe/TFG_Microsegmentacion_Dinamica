import subprocess
from unittest.mock import patch

import interfaces_creator


def completed(command, returncode=0, stdout=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout)


def test_configurar_firewall_base_creates_isolated_zone_and_wan_nat():
    commands = []
    firewall_config = "\n".join(
        [
            "firewall.@zone[0]=zone",
            "firewall.@zone[0].name='lan'",
            "firewall.@zone[1]=zone",
            "firewall.@zone[1].name='wan'",
        ]
    )

    def fake_run(command, **kwargs):
        commands.append(command)
        stdout = firewall_config if command == ["uci", "-q", "show", "firewall"] else ""
        return completed(command, stdout=stdout)

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.configurar_firewall_base() is True

    assert ["sysctl", "-w", "net.ipv4.ip_forward=1"] in commands
    assert ["uci", "set", "firewall.tfg_devices.forward=REJECT"] in commands
    assert [
        "uci",
        "set",
        "firewall.tfg_allow_marked_peers.mark=0x100/0x100",
    ] in commands
    assert [
        "uci",
        "set",
        "firewall.tfg_allow_marked_peers.target=ACCEPT",
    ] in commands
    assert ["uci", "set", "firewall.tfg_devices_wan.src=tfg_devices"] in commands
    assert ["uci", "set", "firewall.tfg_devices_wan.dest=wan"] in commands
    assert ["uci", "set", "firewall.@zone[1].masq=1"] in commands
    assert ["/etc/init.d/firewall", "reload"] in commands


def test_configurar_firewall_base_fails_when_wan_zone_is_missing():
    firewall_config = "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'"

    with patch.object(
        interfaces_creator.subprocess,
        "run",
        return_value=completed([], stdout=firewall_config),
    ) as run:
        assert interfaces_creator.configurar_firewall_base() is False

    run.assert_called_once_with(
        ["uci", "-q", "show", "firewall"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_crear_macvlan_adds_network_to_isolated_zone():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[:3] == ["uci", "-q", "del_list"]:
            return completed(command, returncode=1)
        return completed(command)

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.crear_macvlan("v_020000000001", "192.168.10.1") is True

    assert [
        "ip",
        "link",
        "add",
        "link",
        "phy0-ap0",
        "name",
        "v_020000000001",
        "type",
        "macvlan",
        "mode",
        "bridge",
    ] in commands
    assert [
        "uci",
        "add_list",
        "firewall.tfg_devices.network=v_020000000001",
    ] in commands
    assert ["ifup", "v_020000000001"] in commands


def test_crear_macvlan_uses_configured_parent_interface():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return completed(command)

    with (
        patch.object(interfaces_creator, "PARENT_INTERFACE", "phy4-ap0"),
        patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run),
    ):
        assert interfaces_creator.crear_macvlan(
            "v_020000000001", "192.168.10.1"
        ) is True

    create = next(command for command in commands if command[:3] == ["ip", "link", "add"])
    assert create[3:5] == ["link", "phy4-ap0"]


def test_reconcile_adds_only_missing_active_interfaces_and_reloads_once():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command == ["uci", "-q", "get", "firewall.tfg_devices"]:
            return completed(command, stdout="zone\n")
        if command == ["uci", "-q", "get", "firewall.tfg_devices.network"]:
            return completed(command, stdout="v_020000000001\n")
        if command == ["uci", "-q", "get", "network.v_020000000002"]:
            return completed(command, stdout="interface\n")
        return completed(command)

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.reconciliar_interfaces_firewall(
            ["v_020000000002", "v_020000000001", "v_020000000002"]
        ) is True

    assert [
        "uci",
        "add_list",
        "firewall.tfg_devices.network=v_020000000002",
    ] in commands
    assert [
        "uci",
        "add_list",
        "firewall.tfg_devices.network=v_020000000001",
    ] not in commands
    assert commands.count(["uci", "commit", "firewall"]) == 1
    assert commands.count(["/etc/init.d/firewall", "reload"]) == 1


def test_reconcile_does_not_reload_when_all_interfaces_are_members():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command == ["uci", "-q", "get", "firewall.tfg_devices"]:
            return completed(command, stdout="zone\n")
        return completed(command, stdout="v_020000000001\n")

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.reconciliar_interfaces_firewall(
            ["v_020000000001"]
        ) is True

    assert ["uci", "commit", "firewall"] not in commands
    assert ["/etc/init.d/firewall", "reload"] not in commands


def test_reconcile_rejects_active_interface_without_uci_network():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command == ["uci", "-q", "get", "firewall.tfg_devices"]:
            return completed(command, stdout="zone\n")
        if command == ["uci", "-q", "get", "firewall.tfg_devices.network"]:
            return completed(command, returncode=1)
        if command == ["uci", "-q", "get", "network.v_020000000001"]:
            return completed(command, returncode=1)
        return completed(command)

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.reconciliar_interfaces_firewall(
            ["v_020000000001"]
        ) is False

    assert ["uci", "commit", "firewall"] not in commands
    assert ["/etc/init.d/firewall", "reload"] not in commands


def test_crear_macvlan_rolls_back_after_a_critical_failure():
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command == ["uci", "set", "network.v_020000000001.proto=static"]:
            return completed(command, returncode=1)
        return completed(command)

    with patch.object(interfaces_creator.subprocess, "run", side_effect=fake_run):
        assert interfaces_creator.crear_macvlan("v_020000000001", "192.168.10.1") is False

    assert ["ifdown", "v_020000000001"] in commands
    assert ["uci", "-q", "delete", "network.v_020000000001"] in commands
    assert ["ip", "link", "delete", "v_020000000001"] in commands


def test_rejects_unsafe_interface_and_public_gateway_values():
    with patch.object(interfaces_creator.subprocess, "run") as run:
        assert interfaces_creator.crear_macvlan("bad;name", "192.168.10.1") is False
        assert interfaces_creator.crear_macvlan("v_safe", "8.8.8.8") is False

    run.assert_not_called()
