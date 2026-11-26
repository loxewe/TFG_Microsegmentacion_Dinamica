import importlib
import sys
import types
from unittest.mock import Mock, call, patch

import pytest


class DHCP:
    pass


class BOOTP:
    pass


class Ether:
    pass


class IP:
    pass


class UDP:
    pass


class FakePacket:
    def __init__(self, mac, requested_ip, hostname=None):
        options = [
            ("message-type", 3),
            ("requested_addr", requested_ip),
        ]
        if hostname is not None:
            options.append(("hostname", hostname))
        self.layers = {
            DHCP: types.SimpleNamespace(options=options),
            BOOTP: types.SimpleNamespace(op=1, ciaddr="0.0.0.0"),
            Ether: types.SimpleNamespace(src=mac),
        }

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]


def import_controller_without_scapy():
    fake_all = types.ModuleType("scapy.all")
    fake_all.__all__ = [
        "DHCP",
        "BOOTP",
        "Ether",
        "IP",
        "UDP",
        "sendp",
    ]
    fake_all.DHCP = DHCP
    fake_all.BOOTP = BOOTP
    fake_all.Ether = Ether
    fake_all.IP = IP
    fake_all.UDP = UDP
    fake_all.sendp = lambda *args, **kwargs: None
    fake_scapy = types.ModuleType("scapy")
    fake_scapy.all = fake_all

    sys.modules.pop("controlador_aut", None)
    with patch.dict(
        sys.modules,
        {"scapy": fake_scapy, "scapy.all": fake_all},
    ):
        return importlib.import_module("controlador_aut")


def test_request_after_restart_starts_provisioning_and_sends_deferred_ack():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    device = {
        "nombre_vlan": "v_020000000001",
        "ip_gateway": "192.168.10.1",
        "ip_cliente": "192.168.10.100",
        "creada": False,
    }
    first_request = FakePacket(mac, device["ip_cliente"])
    latest_request = FakePacket(mac, device["ip_cliente"])
    created_threads = []
    sent_packets = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.target = target
            self.args = args
            self.daemon = daemon
            created_threads.append(self)

        def start(self):
            return None

    controller.DISPOSITIVOS = {mac: device}
    controller.en_creacion.clear()
    controller.pending_requests.clear()

    with (
        patch.object(controller.threading, "Thread", FakeThread),
        patch.object(controller, "crear_macvlan", return_value=True),
        patch.object(controller, "registrar_dispositivo", return_value=True),
        patch.object(controller, "guardar_bbdd"),
        patch.object(controller, "craft_dhcp_response", return_value="ACK"),
        patch.object(
            controller,
            "sendp",
            side_effect=lambda packet, **kwargs: sent_packets.append(packet),
        ),
    ):
        controller.dhcp(first_request)
        controller.dhcp(latest_request)

        assert len(created_threads) == 1
        assert controller.pending_requests[mac]["pkt"] is latest_request
        assert mac in controller.en_creacion

        created_threads[0].target(*created_threads[0].args)

    assert controller.DISPOSITIVOS[mac]["creada"] is True
    assert mac not in controller.en_creacion
    assert mac not in controller.pending_requests
    assert sent_packets == ["ACK"]


def test_invalid_requested_address_does_not_start_provisioning():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {
        mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": False,
        }
    }
    controller.en_creacion.clear()
    controller.pending_requests.clear()
    packet = FakePacket(mac, "192.168.99.100")

    with (
        patch.object(controller, "iniciar_aprovisionamiento") as start,
        patch.object(controller, "craft_dhcp_response", return_value="NAK"),
        patch.object(controller, "sendp"),
    ):
        controller.dhcp(packet)

    start.assert_not_called()
    assert mac not in controller.pending_requests


def test_dhcp_hostname_is_normalized_and_persisted_only_when_changed():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {
        mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": True,
        }
    }
    packet = FakePacket(mac, "192.168.10.100", b"  living-room-tv\x00 ")

    with (
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(controller, "craft_dhcp_response", return_value="ACK"),
        patch.object(controller, "sendp"),
    ):
        controller.dhcp(packet)
        controller.dhcp(packet)

    assert controller.DISPOSITIVOS[mac]["hostname"] == "living-room-tv"
    # Cada ACK guarda la hora de concesión; el nombre solo se guarda la primera vez.
    assert save.call_count == 3


@pytest.mark.parametrize(
    "value",
    [None, b"\x00", "x" * 254, object()],
)
def test_invalid_dhcp_hostnames_are_ignored(value):
    controller = import_controller_without_scapy()

    assert controller.normalizar_hostname(value) is None


def test_policy_watcher_retries_under_network_lock_until_stopped():
    controller = import_controller_without_scapy()
    stop_event = Mock()
    stop_event.wait.side_effect = [False, False, True]

    def reload():
        assert controller.os_lock.locked()
        return False

    with patch.object(controller, "recargar_politicas", side_effect=reload) as reload:
        controller.vigilar_politicas(stop_event)

    assert reload.call_count == 2
    assert not controller.os_lock.locked()


def test_runtime_reconciliation_uses_existing_macvlan_interfaces():
    controller = import_controller_without_scapy()
    existing_mac = "02:00:00:00:00:01"
    missing_mac = "02:00:00:00:00:02"
    controller.DISPOSITIVOS = {
        existing_mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": False,
        },
        missing_mac: {
            "nombre_vlan": "v_020000000002",
            "ip_gateway": "192.168.11.1",
            "ip_cliente": "192.168.11.100",
            "creada": True,
        },
    }

    def exists(path):
        return path.endswith("v_020000000001")

    with (
        patch.object(controller.os.path, "exists", side_effect=exists),
        patch.object(controller, "interfaz_en_padre_actual", return_value=True),
        patch.object(
            controller,
            "obtener_clientes_runtime",
            return_value={existing_mac},
        ),
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(
            controller, "reconciliar_interfaces_firewall", return_value=True
        ) as reconcile_firewall,
        patch.object(
            controller, "reconciliar_dispositivos", return_value=True
        ) as reconcile,
    ):
        assert controller.reconciliar_estado_runtime() is True

    assert controller.DISPOSITIVOS[existing_mac]["creada"] is True
    assert controller.DISPOSITIVOS[missing_mac]["creada"] is False
    reconcile_firewall.assert_called_once_with(["v_020000000001"])
    reconcile.assert_called_once_with(
        {
            existing_mac: {
                "client_ip": "192.168.10.100",
                "gateway_ip": "192.168.10.1",
            }
        }
    )
    save.assert_called_once_with()


def test_failed_runtime_reconciliation_does_not_publish_new_flags():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {
        mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": False,
        }
    }

    with (
        patch.object(controller.os.path, "exists", return_value=True),
        patch.object(controller, "interfaz_en_padre_actual", return_value=True),
        patch.object(
            controller, "obtener_clientes_runtime", return_value={mac}
        ),
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(
            controller, "reconciliar_interfaces_firewall", return_value=True
        ),
        patch.object(
            controller, "reconciliar_dispositivos", return_value=False
        ),
    ):
        assert controller.reconciliar_estado_runtime() is False

    assert controller.DISPOSITIVOS[mac]["creada"] is False
    save.assert_not_called()


def test_stale_interface_does_not_reactivate_inactive_device():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {
        mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": False,
        }
    }

    with (
        patch.object(controller.os.path, "exists", return_value=True),
        patch.object(controller, "interfaz_en_padre_actual", return_value=True),
        patch.object(controller, "obtener_clientes_runtime", return_value=set()),
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(
            controller, "reconciliar_interfaces_firewall", return_value=True
        ) as reconcile_firewall,
        patch.object(
            controller, "reconciliar_dispositivos", return_value=True
        ) as reconcile,
    ):
        assert controller.reconciliar_estado_runtime() is True

    reconcile_firewall.assert_called_once_with([])
    reconcile.assert_called_once_with({})
    assert controller.DISPOSITIVOS[mac]["creada"] is False
    save.assert_not_called()


def test_main_stops_policy_watcher_when_capture_fails():
    controller = import_controller_without_scapy()
    stop_event = Mock()
    with (
        patch.object(controller.threading, "Event", return_value=stop_event),
        patch.object(controller.threading, "Thread") as thread,
        patch.object(controller, "reconciliar_estado_runtime", return_value=True),
        patch.object(controller, "sniff", create=True, side_effect=RuntimeError("capture")),
        pytest.raises(RuntimeError, match="capture"),
    ):
        controller.main()

    assert thread.call_args_list == [
        call(target=controller.vigilar_politicas, args=(stop_event,), daemon=True),
        call(target=controller.vigilar_concesiones, args=(stop_event,), daemon=True),
    ]
    assert thread.return_value.start.call_count == 2
    stop_event.set.assert_called_once()


def test_lease_watcher_is_not_started_when_expiry_is_disabled():
    controller = import_controller_without_scapy()
    controller.LEASE_EXPIRY_ENABLED = False
    stop_event = Mock()
    with (
        patch.object(controller.threading, "Event", return_value=stop_event),
        patch.object(controller.threading, "Thread") as thread,
        patch.object(controller, "reconciliar_estado_runtime", return_value=True),
        patch.object(controller, "sniff", create=True, side_effect=RuntimeError("capture")),
        pytest.raises(RuntimeError, match="capture"),
    ):
        controller.main()

    thread.assert_called_once_with(
        target=controller.vigilar_politicas, args=(stop_event,), daemon=True
    )


def test_setup_red_does_not_start_service_when_base_policies_fail():
    controller = import_controller_without_scapy()
    with (
        patch.object(controller, "configurar_politicas_base", return_value=False),
        patch.object(controller.threading, "Thread") as thread,
        patch.object(controller, "sniff", create=True) as sniff,
        pytest.raises(SystemExit),
    ):
        controller.setup_red()
    thread.assert_not_called()
    sniff.assert_not_called()


def test_setup_red_reconciles_interfaces_after_rebuilding_base_firewall():
    controller = import_controller_without_scapy()
    with (
        patch.object(controller, "configurar_politicas_base", return_value=True),
        patch.object(
            controller, "reconciliar_estado_runtime", return_value=True
        ) as reconcile,
    ):
        controller.setup_red()

    reconcile.assert_called_once_with()


def test_main_starts_dhcp_without_reconfiguring_network():
    controller = import_controller_without_scapy()
    with (
        patch.object(controller, "configurar_politicas_base") as configure,
        patch.object(controller, "servir_dhcp") as serve,
    ):
        controller.main([])
    configure.assert_not_called()
    serve.assert_called_once_with()


def _segmento(creada=True, ultima_concesion=None):
    device = {
        "nombre_vlan": "v_020000000001",
        "ip_gateway": "192.168.10.1",
        "ip_cliente": "192.168.10.100",
        "creada": creada,
    }
    if ultima_concesion is not None:
        device["ultima_concesion"] = ultima_concesion
    return device


def _revisar(controller, now, stations):
    with (
        patch.object(controller.time, "time", return_value=now),
        patch.object(
            controller, "estaciones_asociadas", return_value=stations
        ) as associated,
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(controller, "eliminar_dispositivo") as remove_policy,
        patch.object(controller, "eliminar_macvlan") as remove_interface,
    ):
        retired = controller.revisar_concesiones()
    return retired, associated, save, remove_policy, remove_interface


def test_expired_lease_of_absent_client_retires_segment_and_keeps_inventory():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    expired = 1000.0 - controller.LEASE_TIME - controller.LEASE_GRACE - 1
    controller.DISPOSITIVOS = {mac: _segmento(ultima_concesion=expired)}
    controller.pending_requests[mac] = {"pkt": object(), "time": 0}

    retired, _, save, remove_policy, remove_interface = _revisar(
        controller, 1000.0, set()
    )

    assert retired == [mac]
    remove_policy.assert_called_once_with(mac)
    remove_interface.assert_called_once_with("v_020000000001")
    save.assert_called_once_with()
    assert controller.DISPOSITIVOS[mac]["creada"] is False
    assert controller.DISPOSITIVOS[mac]["ip_cliente"] == "192.168.10.100"
    assert mac not in controller.pending_requests


def test_renewed_lease_keeps_segment_without_querying_stations():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: _segmento(ultima_concesion=900.0)}

    retired, associated, _, remove_policy, remove_interface = _revisar(
        controller, 1000.0, set()
    )

    assert retired == []
    associated.assert_not_called()
    remove_policy.assert_not_called()
    remove_interface.assert_not_called()
    assert controller.DISPOSITIVOS[mac]["creada"] is True


def test_expired_lease_of_associated_client_keeps_segment():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: _segmento(ultima_concesion=0.0)}

    retired, _, _, remove_policy, remove_interface = _revisar(
        controller, 100000.0, {mac}
    )

    assert retired == []
    remove_policy.assert_not_called()
    remove_interface.assert_not_called()
    assert controller.DISPOSITIVOS[mac]["creada"] is True


def test_unknown_station_list_retires_nothing():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: _segmento(ultima_concesion=0.0)}

    retired, _, _, remove_policy, remove_interface = _revisar(
        controller, 100000.0, None
    )

    assert retired == []
    remove_policy.assert_not_called()
    remove_interface.assert_not_called()
    assert controller.DISPOSITIVOS[mac]["creada"] is True


@pytest.mark.parametrize(
    "device",
    [
        _segmento(creada=False, ultima_concesion=0.0),
        _segmento(creada=True),
    ],
)
def test_inactive_or_undated_segments_are_not_retired(device):
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: device}

    retired, associated, *_ = _revisar(controller, 100000.0, set())

    assert retired == []
    associated.assert_not_called()


def test_segment_being_provisioned_is_not_retired():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: _segmento(ultima_concesion=0.0)}
    controller.en_creacion.add(mac)

    retired, associated, *_ = _revisar(controller, 100000.0, set())

    assert retired == []
    associated.assert_not_called()


def test_station_dump_is_parsed_and_failures_return_none():
    controller = import_controller_without_scapy()
    output = (
        "Station 02:00:00:00:00:0A (on phy0-ap0)\n"
        "\tinactive time:\t10 ms\n"
        "Station 02:00:00:00:00:0b (on phy0-ap0)\n"
    )
    ok = Mock(returncode=0, stdout=output)
    with patch.object(controller.subprocess, "run", return_value=ok) as run:
        assert controller.estaciones_asociadas() == {
            "02:00:00:00:00:0a",
            "02:00:00:00:00:0b",
        }
    assert run.call_args.args[0] == [
        "iw", "dev", controller.INTERFACE, "station", "dump"
    ]

    failed = Mock(returncode=1, stdout="")
    with patch.object(controller.subprocess, "run", return_value=failed):
        assert controller.estaciones_asociadas() is None
    with patch.object(controller.subprocess, "run", side_effect=OSError("iw")):
        assert controller.estaciones_asociadas() is None


def test_lease_time_comes_from_environment_with_safe_fallback():
    for value, expected in [("300", 300), ("abc", 3600), ("10", 3600), ("", 3600)]:
        with patch.dict("os.environ", {"TFG_LEASE_TIME": value}):
            controller = import_controller_without_scapy()
        assert controller.LEASE_TIME == expected
    with patch.dict("os.environ", {"TFG_LEASE_EXPIRY": "0"}):
        controller = import_controller_without_scapy()
    assert controller.LEASE_EXPIRY_ENABLED is False


def test_reconciliation_dates_active_segments_without_lease():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {mac: _segmento(creada=True)}

    with (
        patch.object(controller.os.path, "exists", return_value=True),
        patch.object(controller, "interfaz_en_padre_actual", return_value=True),
        patch.object(controller, "obtener_clientes_runtime", return_value={mac}),
        patch.object(controller.time, "time", return_value=5000.0),
        patch.object(controller, "guardar_bbdd") as save,
        patch.object(controller, "reconciliar_interfaces_firewall", return_value=True),
        patch.object(controller, "reconciliar_dispositivos", return_value=True),
    ):
        assert controller.reconciliar_estado_runtime() is True

    assert controller.DISPOSITIVOS[mac]["ultima_concesion"] == 5000.0
    save.assert_called_once_with()
