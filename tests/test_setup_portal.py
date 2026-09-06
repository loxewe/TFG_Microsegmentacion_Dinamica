import importlib
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from router_adapters import (
    AdapterCapabilities,
    AdapterMaturity,
    Credentials,
    DetectionResult,
    FeatureState,
    RouterStatus,
)
from router_integration import RouterInspection


with patch("subprocess.run"):
    setup_portal = importlib.import_module("setup_portal")


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        command,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.fixture(autouse=True)
def reset_setup_state():
    setup_portal.update_setup_state(
        "idle",
        "Esperando configuración.",
    )


def test_import_does_not_change_router_state():
    with patch("subprocess.run") as run:
        importlib.reload(setup_portal)

    run.assert_not_called()


def test_uci_setup_complete_requires_exact_value_one():
    with patch.object(
        setup_portal.subprocess,
        "run",
        return_value=completed([], stdout="1\n"),
    ):
        assert setup_portal.is_setup_complete() is True

    with patch.object(
        setup_portal.subprocess,
        "run",
        return_value=completed([], stdout="0\n"),
    ):
        assert setup_portal.is_setup_complete() is False


def test_main_prepares_setup_without_touching_uhttpd():
    with (
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "prepare_setup_network", return_value=True
        ) as prepare_setup,
        patch.object(setup_portal, "prepare_normal_network") as prepare_normal,
        patch.object(setup_portal.app, "run") as serve,
        patch.object(setup_portal.subprocess, "run") as run,
    ):
        assert setup_portal.main(["--listen", "127.0.0.1", "--port", "8080"]) == 0

    prepare_setup.assert_called_once_with()
    prepare_normal.assert_not_called()
    serve.assert_called_once_with(
        host="127.0.0.1",
        port=8080,
        debug=False,
        use_reloader=False,
    )
    assert all("uhttpd" not in str(invocation) for invocation in run.call_args_list)


def test_main_prepares_normal_mode():
    with (
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "prepare_setup_network") as prepare_setup,
        patch.object(
            setup_portal, "prepare_normal_network", return_value=True
        ) as prepare_normal,
        patch.object(setup_portal.app, "run"),
    ):
        assert setup_portal.main([]) == 0

    prepare_setup.assert_not_called()
    prepare_normal.assert_called_once_with()


def test_setup_mode_uses_services_and_never_shell_kill():
    with patch.object(
        setup_portal.subprocess,
        "run",
        return_value=completed([]),
    ) as run:
        assert setup_portal.prepare_setup_network() is True

    commands = [invocation.args[0] for invocation in run.call_args_list]
    assert ["/etc/init.d/tfg-dhcp", "stop"] in commands
    assert ["/etc/init.d/tfg-discovery", "stop"] in commands
    assert ["/etc/init.d/tfg-zeek", "stop"] in commands
    assert ["nft", "delete", "table", "netdev", "tfg_l2"] in commands
    assert ["nft", "delete", "table", "inet", "tfg_l3"] in commands
    assert ["uci", "set", "dhcp.wifi.ignore=0"] in commands
    assert ["uci", "add_list", setup_portal.CAPTIVE_DNS_REDIRECT] in commands
    assert not any(isinstance(command, str) for command in commands)
    assert not any("kill" in command for command in commands)


def test_network_setup_is_explicit():
    with (
        patch.object(
            setup_portal.subprocess,
            "run",
            return_value=completed([]),
        ) as run,
        patch.object(
            setup_portal,
            "resolve_access_point_interface",
            return_value="phy4-ap0",
        ),
    ):
        assert setup_portal.run_network_setup() is True

    invocation = run.call_args
    assert invocation.args[0] == (
        [
            setup_portal.sys.executable,
            str(setup_portal.PROJECT_DIR / "controlador_aut.py"),
            "--setup-red",
        ]
    )
    assert invocation.kwargs["env"]["TFG_INTERFACE"] == "phy4-ap0"
    assert invocation.kwargs["timeout"] == 120


def test_access_point_configuration_enables_station_isolation():
    with (
        patch.object(setup_portal, "_command_ok", return_value=True) as command,
        patch.object(
            setup_portal,
            "access_point_settings",
            return_value=("radio1", "wifinet1"),
        ),
        patch.object(
            setup_portal,
            "_uci_value",
            side_effect=lambda option, default: {
                "wireless.wifinet1.device": "radio0",
                "wireless.wifinet1.network": "wifi",
                "wireless.radio0.band": "2g",
                "wireless.radio0.channel": "6",
                "wireless.radio0.htmode": "HT20",
                "wireless.radio0.country": "ES",
            }.get(option, default),
        ),
    ):
        assert setup_portal.configure_access_point("TFG", "wifi-password") is True

    commands = [invocation.args[0] for invocation in command.call_args_list]
    assert ["uci", "set", "wireless.default_radio1.disabled=1"] in commands
    assert ["uci", "-q", "delete", "network.wifi.device"] in commands
    assert ["uci", "set", "wireless.radio1.disabled=0"] in commands
    assert ["uci", "set", "wireless.radio1.band=2g"] in commands
    assert ["uci", "set", "wireless.radio1.channel=6"] in commands
    assert ["uci", "set", "wireless.wifinet1.device=radio1"] in commands
    assert ["uci", "set", "wireless.wifinet1.isolate=1"] in commands
    assert ["uci", "set", "wireless.wifinet1.bridge_isolate=1"] in commands
    assert ["uci", "set", "tfg.discovery=service"] in commands
    assert ["uci", "set", "tfg.dhcp.interface=auto"] in commands
    assert ["uci", "commit", "network"] in commands
    assert ["wifi", "reload"] in commands


def test_access_point_isolation_requires_both_uci_options():
    responses = [
        completed([], stdout="1\n"),
        completed([], stdout="1\n"),
    ]
    with (
        patch.object(setup_portal, "_run", side_effect=responses),
        patch.object(
            setup_portal,
            "access_point_settings",
            return_value=("radio1", "custom_ap"),
        ),
    ):
        assert setup_portal.access_point_isolated() is True

    responses = [
        completed([], stdout="1\n"),
        completed([], stdout="0\n"),
    ]
    with (
        patch.object(setup_portal, "_run", side_effect=responses),
        patch.object(
            setup_portal,
            "access_point_settings",
            return_value=("radio1", "custom_ap"),
        ),
    ):
        assert setup_portal.access_point_isolated() is False


def test_runtime_ap_interface_is_resolved_by_radio_and_section():
    status = {
        "radio1": {
            "interfaces": [
                {"section": "wifinet1", "ifname": "phy4-ap0"},
            ]
        }
    }
    with (
        patch.object(
            setup_portal,
            "access_point_settings",
            return_value=("radio1", "wifinet1"),
        ),
        patch.object(
            setup_portal,
            "_run",
            return_value=completed([], stdout=json.dumps(status)),
        ),
    ):
        assert setup_portal.resolve_access_point_interface() == "phy4-ap0"


def test_adapter_shutdown_detects_once_and_verifies_through_coordinator():
    router = {
        "mode": "adapter",
        "base_url": "http://router.test",
        "allow_experimental": False,
        "expected_adapter": "glinet",
        "selection": "glinet",
    }
    report = Mock()
    report.adapter.adapter_id = "glinet"
    result = Mock()
    result.verification.success = True
    coordinator = Mock()
    coordinator.detect.return_value = report
    coordinator.disable_detected_wifi.return_value = result
    with patch.object(
        setup_portal,
        "RouterCoordinator",
        return_value=coordinator,
    ):
        success = setup_portal.shutdown_isp_router(
            router,
            "admin-password",
            "root",
            "Home",
            "wifi-password",
        )

    assert success is True
    coordinator.detect.assert_called_once_with(
        "http://router.test",
        allow_experimental=False,
    )
    coordinator.disable_detected_wifi.assert_called_once_with(
        report,
        Credentials(password="admin-password", username="root"),
    )


def test_legacy_shutdown_remains_explicit_compatibility_path():
    router = {
        "mode": "legacy",
        "script": "/switcher.py",
        "selection": "zte_h298a",
        "base_url": "http://router.test",
    }
    with patch.object(setup_portal, "_command_ok", return_value=True) as command:
        success = setup_portal.shutdown_isp_router(
            router,
            "admin-password",
            "",
            "Home",
            "wifi-password",
        )

    assert success is True
    command.assert_called_once_with(
        ["python3", "/switcher.py", "admin-password", "off"],
        timeout=60,
    )


def test_success_marks_complete_only_after_services_and_tables():
    router = {"mode": "adapter", "base_url": "http://router.test"}
    order = Mock()
    with (
        patch.object(
            setup_portal,
            "shutdown_isp_router",
            return_value=True,
        ) as shutdown,
        patch.object(
            setup_portal,
            "configure_access_point",
            return_value=True,
        ) as access_point,
        patch.object(
            setup_portal, "access_point_isolated", return_value=True
        ) as isolated,
        patch.object(
            setup_portal,
            "run_network_setup",
            return_value=True,
        ) as network_setup,
        patch.object(
            setup_portal,
            "configure_setup_dhcp",
            return_value=True,
        ) as setup_dhcp,
        patch.object(
            setup_portal,
            "start_and_wait_for_service",
            return_value=True,
        ) as start_service,
        patch.object(
            setup_portal,
            "verify_policy_tables",
            return_value=True,
        ) as verify_tables,
        patch.object(
            setup_portal,
            "set_setup_complete",
            return_value=True,
        ) as set_complete,
        patch.object(setup_portal, "stop_normal_services"),
    ):
        order.attach_mock(shutdown, "shutdown")
        order.attach_mock(access_point, "access_point")
        order.attach_mock(isolated, "isolated")
        order.attach_mock(network_setup, "network_setup")
        order.attach_mock(setup_dhcp, "setup_dhcp")
        order.attach_mock(start_service, "start_service")
        order.attach_mock(verify_tables, "verify_tables")
        order.attach_mock(set_complete, "set_complete")

        assert setup_portal.finalize_takeover(
            router,
            "admin",
            "root",
            "Home",
            "wifi-password",
        ) is True

    assert order.mock_calls == [
        call.shutdown(
            router,
            "admin",
            "root",
            "Home",
            "wifi-password",
        ),
        call.access_point("Home", "wifi-password"),
        call.isolated(),
        call.network_setup(),
        call.setup_dhcp(False),
        call.start_service("tfg-dhcp"),
        call.start_service("tfg-discovery"),
        call.start_service("tfg-zeek"),
        call.verify_tables(),
        call.set_complete(True),
    ]
    assert setup_portal.current_setup_state()["status"] == "success"


def test_failed_service_keeps_setup_incomplete_and_restores_setup_network():
    router = {"mode": "adapter", "base_url": "http://router.test"}
    with (
        patch.object(
            setup_portal, "shutdown_isp_router", return_value=True
        ),
        patch.object(
            setup_portal, "configure_access_point", return_value=True
        ),
        patch.object(setup_portal, "access_point_isolated", return_value=True),
        patch.object(setup_portal, "run_network_setup", return_value=True),
        patch.object(
            setup_portal, "configure_setup_dhcp", return_value=True
        ),
        patch.object(
            setup_portal,
            "start_and_wait_for_service",
            side_effect=[True, False],
        ),
        patch.object(
            setup_portal, "verify_policy_tables"
        ) as verify_tables,
        patch.object(
            setup_portal, "recover_setup_network", return_value=True
        ) as recover,
        patch.object(
            setup_portal, "set_setup_complete"
        ) as set_complete,
        patch.object(setup_portal, "stop_normal_services"),
    ):
        assert setup_portal.finalize_takeover(
            router,
            "admin",
            "root",
            "Home",
            "wifi-password",
        ) is False

    recover.assert_called_once_with()
    verify_tables.assert_not_called()
    set_complete.assert_not_called()
    state = setup_portal.current_setup_state()
    assert state["status"] == "error"
    assert "tfg-discovery" in state["error"]


def test_setup_status_reports_progress():
    setup_portal.update_setup_state("running", "Iniciando Zeek...")
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
    ):
        response = client.get("/setup/status")

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "running",
        "step": "Iniciando Zeek...",
        "error": None,
        "setup_complete": False,
    }


def test_root_selects_setup_or_dashboard():
    with setup_portal.app.test_client() as client:
        with patch.object(
            setup_portal, "is_setup_complete", return_value=False
        ):
            assert client.get("/").location.endswith("/setup")
        with patch.object(
            setup_portal, "is_setup_complete", return_value=True
        ):
            assert client.get("/").location.endswith("/dashboard")


def test_dashboard_contains_services_devices_and_policy_form():
    device = {
        "mac": "02:00:00:00:00:01",
        "name": "Dispositivo",
        "ip": "192.168.10.100",
        "gateway": "192.168.10.1",
        "created": True,
        "policy": {
            "internet": True,
            "inter_device": False,
            "mdns": True,
            "ssdp": True,
            "broadcast": "block",
        },
        "activity": {
            "last_seen": "2026-09-03 10:00:00 UTC",
            "last_seen_epoch": 1788429600.0,
            "recent": True,
            "connections": 3,
            "bytes_sent": 1536,
            "bytes_received": 4096,
            "destinations": ["203.0.113.8"],
            "dns_queries": ["example.test"],
            "protocols": ["https"],
            "external_attempts": 2,
            "peer_flows": 1,
            "mdns_events": 0,
            "ssdp_events": 1,
            "broadcast_events": 0,
        },
        "enforcement": {
            "status": "applied",
            "differences": [],
            "error": None,
            "controls": {},
        },
    }
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal,
            "get_system_status",
            return_value={
                "dhcp": True,
                "discovery": True,
                "zeek": True,
                "wifi_isolation": True,
                "microsegmentation": True,
            },
        ),
        patch.object(setup_portal, "load_devices", return_value=[device]),
    ):
        response = client.get("/dashboard")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "192.168.10.100" in page
    assert "02:00:00:00:00:01" in page
    assert "Microsegmentación" in page
    assert "Relay mDNS/SSDP" in page
    assert "Aislamiento Wi-Fi" in page
    assert (
        "mDNS, SSDP y broadcast controlan qué tráfico de descubrimiento local "
        "emitido por el dispositivo se reenvía. Interdispositivo permite "
        "conexiones unicast hacia otros dispositivos."
    ) in page
    assert "Interdispositivo" in page
    assert "Gestión de dispositivos" not in page
    assert "Inventario" not in page
    assert page.count(">Activo</span>") == 5
    for service in (
        "DHCP",
        "Zeek",
        "Relay mDNS/SSDP",
        "Aislamiento Wi-Fi",
        "Microsegmentación",
    ):
        title = f"<strong>{service}</strong>"
        assert page.index(title) < page.index(">Activo</span>", page.index(title))
    for subtitle in (
        "Asignación de red",
        "Observabilidad",
        "Descubrimiento autorizado",
        "Separación entre estaciones",
        "Control de tráfico",
    ):
        assert subtitle not in page
    assert ">running</span>" not in page
    assert ">stopped</span>" not in page
    assert ">ON</span>" not in page
    assert ">OFF</span>" not in page
    assert "Interdispositivo 1" in page
    assert (
        "La actividad observada y el estado efectivo se presentan por separado."
        not in page
    )
    assert ".summary-grid + .notice { margin-top: 18px; }" in page
    assert "Actividad Zeek" in page
    assert "example.test" not in page
    assert "1.5 KB" in page
    assert "aplicada en nftables" in page
    assert "MODO NORMAL" not in page
    assert "Sistema operativo" not in page
    assert "Actualización automática" not in page
    assert "Red doméstica segura y observable" not in page
    assert "Actualizado:" in page
    assert "window.setInterval(refreshDashboard, 3000)" in page
    assert "Editar política" in page
    assert "Conectividad" in page
    assert "Descubrimiento local" in page
    assert "Guardar política" in page
    assert page.count('<fieldset class="policy-group">') == 2
    assert page.count('<label class="policy-toggle">') == 5
    assert "grid-template-columns: repeat(auto-fit, minmax(240px, 1fr))" in page
    assert "grid-template-columns: repeat(3, minmax(0, 1fr))" in page
    assert "flex-direction: column" in page
    assert "white-space: nowrap" in page
    assert ">Interdispositivo</span>" in page
    assert ">Entre dispositivos</span>" not in page
    assert "Bloqueado" in page
    assert "Permitido" in page
    assert 'select name="broadcast"' not in page
    assert "registrar y permitir" not in page
    assert "pendiente o parcial" in page
    assert 'href="/devices/02:00:00:00:00:01"' in page
    assert "/devices/02:00:00:00:00:01/policy" in page


def detail_device():
    policy = {
        "internet": True,
        "inter_device": False,
        "mdns": True,
        "ssdp": False,
        "broadcast": "block",
    }
    controls = {
        name: {
            "configured": value,
            "effective": value,
            "status": "applied",
        }
        for name, value in policy.items()
    }
    controls["discovery"] = {
        "configured": True,
        "effective": True,
        "status": "applied",
    }
    return {
        "mac": "02:00:00:00:00:01",
        "name": "Televisor",
        "alias": "Televisor",
        "hostname": "living-room-tv",
        "name_source": "alias",
        "ip": "192.168.10.100",
        "gateway": "192.168.10.1",
        "created": True,
        "policy": policy,
        "activity": {
            "last_seen": "2026-09-03 10:00:00 UTC",
            "last_seen_epoch": 1788429600.0,
            "recent": True,
            "connections": 3,
            "bytes_sent": 1536,
            "bytes_received": 4096,
            "destinations": ["203.0.113.8"],
            "dns_queries": ["example.test"],
            "protocols": ["ssl"],
            "external_attempts": 2,
            "peer_flows": 1,
            "mdns_events": 1,
            "ssdp_events": 0,
            "broadcast_events": 0,
            "source_status": "available",
            "source_error": None,
        },
        "enforcement": {
            "status": "applied",
            "differences": [],
            "error": None,
            "controls": controls,
        },
    }


def dashboard_device(index, created):
    device = detail_device()
    device["mac"] = f"02:00:00:00:00:{index:02x}"
    device["name"] = f"Dispositivo {index}"
    device["created"] = created
    device["observations"] = []
    device["trusted"] = False
    if not created:
        device["enforcement"]["status"] = "inactive"
    return device


def render_dashboard(devices):
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal,
            "get_system_status",
            return_value={
                "dhcp": True,
                "discovery": True,
                "zeek": True,
                "wifi_isolation": True,
                "microsegmentation": True,
            },
        ),
        patch.object(setup_portal, "load_devices", return_value=devices),
    ):
        response = client.get("/dashboard")

    return response.status_code, response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("active_count", "inactive_count"),
    [(0, 0), (2, 0), (0, 2), (2, 2), (3, 2), (2, 3)],
)
def test_dashboard_card_groups_handle_empty_even_and_odd_counts(
    active_count, inactive_count
):
    active = [dashboard_device(index + 1, True) for index in range(active_count)]
    inactive = [
        dashboard_device(active_count + index + 1, False)
        for index in range(inactive_count)
    ]

    status_code, page = render_dashboard(inactive + active)

    assert status_code == 200
    assert page.count('class="device-card"') == active_count + inactive_count
    assert ('data-state="active"' in page) is bool(active_count)
    assert ('data-state="inactive"' in page) is bool(inactive_count)
    assert ("Dispositivos activos (" in page) is bool(active_count)
    assert ("Dispositivos inactivos (" in page) is bool(inactive_count)
    assert ("Todavía no hay dispositivos registrados" in page) is not bool(
        active_count + inactive_count
    )


def test_dashboard_card_grid_centers_odd_last_card_and_stacks_on_mobile():
    _, page = render_dashboard([dashboard_device(1, True)])

    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in page
    assert ".device-card:last-child:nth-child(odd)" in page
    assert "grid-column: 1 / -1" in page
    assert "@media (max-width: 800px)" in page
    assert ".device-grid { grid-template-columns: 1fr; }" in page


def test_dashboard_refresh_preserves_an_open_policy_editor():
    _, page = render_dashboard([dashboard_device(1, True)])

    editor_guard = 'document.querySelector("details[open]")'
    skip_refresh = (
        "if (document.hidden || editing || dashboardRefreshRunning) return;"
    )
    replacement = "currentNode.replaceWith(incomingNode);"

    assert editor_guard in page
    assert skip_refresh in page
    assert (
        page.index(editor_guard)
        < page.index(skip_refresh)
        < page.index(replacement)
    )


def test_device_detail_explains_configured_application_and_observed_state():
    device = detail_device()
    device["observations"] = setup_portal.build_protocol_observations(device)
    device["trusted"] = False
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal, "load_devices", return_value=[device]
        ),
    ):
        response = client.get("/devices/02:00:00:00:00:01")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Televisor" in page
    assert "Política y aplicación" in page
    assert "Actividad observada por Zeek" in page
    assert (
        "Zeek indica qué protocolos aparecen en la muestra."
        not in page
    )
    assert "MODO NORMAL" not in page
    assert "Actualización automática" not in page
    assert "window.setInterval(refreshDeviceDetail, 3000)" in page
    assert "Trazabilidad" not in page
    assert "policies.json" not in page
    assert "Interdispositivo" in page
    assert "El hostname procede del cliente DHCP" in page
    assert "Confiar habilita el tráfico interdispositivo" in page
    assert "Flujos interdispositivo" in page
    assert "Conexiones totales de la muestra" in page
    assert "Conexiones de la muestra" not in page
    assert "<tr><td>mDNS</td><td>1</td></tr>" in page
    assert "<tr><td>SSDP</td><td>0</td></tr>" in page
    assert "<tr><td>Broadcast</td><td>0</td></tr>" in page
    assert "mDNS / SSDP / broadcast" not in page
    assert (
        ".policy-table th:nth-child(2), .policy-table td:nth-child(2)"
        in page
    )
    assert "text-align: center;" in page
    assert "flex-direction: column;" in page
    assert "align-items: center;" in page
    assert "Permitido" in page
    assert "Aplicada" in page
    assert "fuente disponible" in page
    assert "Descubrimiento observado" in page
    assert "mDNS observado, autorizado y aplicado" in page
    assert "Confiar en este dispositivo" in page
    assert 'name="return_to" value="detail"' in page
    assert page.count('class="policy-table-toggle"') == 5
    assert "multicast de descubrimiento" not in page
    assert "Protocolos:" not in page
    assert "Destinos:" not in page
    assert "DNS:" not in page


def test_device_detail_uses_clear_application_statuses_without_effective_column():
    device = detail_device()
    device["enforcement"]["controls"]["internet"]["status"] = "applied"
    device["enforcement"]["controls"]["inter_device"]["status"] = "inactive"
    device["enforcement"]["controls"]["mdns"]["status"] = "different"
    device["enforcement"]["controls"]["ssdp"]["status"] = "unavailable"
    device["observations"] = setup_portal.build_protocol_observations(device)
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "load_devices", return_value=[device]),
    ):
        response = client.get("/devices/02:00:00:00:00:01")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "<th>Aplicación</th>" in page
    assert "<th>Efectivo</th>" not in page
    assert "<th>Estado</th>" not in page
    assert page.count('data-label="Aplicación"') == 5
    assert 'data-label="Efectivo"' not in page
    assert "Aplicada" in page
    assert "Bloqueo aplicado" in page
    assert "Pendiente de sincronizar" in page
    assert "No disponible" in page


def test_detail_refresh_preserves_an_unsaved_policy_change():
    device = detail_device()
    device["observations"] = setup_portal.build_protocol_observations(device)
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "load_devices", return_value=[device]),
    ):
        response = client.get("/devices/02:00:00:00:00:01")

    page = response.get_data(as_text=True)
    dirty_listener = (
        'event.target.closest("#detail-policy-panel .policy-form")'
    )
    dirty_assignment = "detailPolicyDirty = true;"
    refresh_guard = (
        "if (document.hidden || editing || detailPolicyDirty || "
        "detailRefreshRunning) return;"
    )
    replacement = "currentNode.replaceWith(incomingNode);"

    assert response.status_code == 200
    assert "let detailPolicyDirty = false;" in page
    assert dirty_listener in page
    assert dirty_assignment in page
    assert refresh_guard in page
    assert (
        page.index(dirty_listener)
        < page.index(dirty_assignment)
        < page.index(refresh_guard)
        < page.index(replacement)
    )


def test_device_summary_counts_only_relevant_active_states():
    devices = [
        {
            "created": True,
            "activity": {"recent": True, "source_status": "partial"},
            "enforcement": {"status": "different"},
        },
        {
            "created": True,
            "activity": {"recent": False, "source_status": "available"},
            "enforcement": {"status": "unavailable"},
        },
        {
            "created": False,
            "activity": {"recent": True, "source_status": "unavailable"},
            "enforcement": {"status": "different"},
        },
    ]

    assert setup_portal.summarize_devices(devices) == {
        "total": 3,
        "active": 2,
        "inactive": 1,
        "recent": 1,
        "needs_authorization": 0,
        "policy_different": 1,
        "policy_unavailable": 1,
        "zeek_limited": 1,
    }


def test_dashboard_separates_devices_and_reports_actionable_alerts():
    active = detail_device()
    active["enforcement"]["status"] = "different"
    active["activity"]["source_status"] = "partial"
    active["observations"] = [
        {
            "id": "ssdp",
            "label": "SSDP",
            "events": 1,
            "observed": True,
            "applied": False,
            "needs_authorization": True,
            "message": (
                "Este dispositivo necesita autorización para "
                "descubrimiento local mediante SSDP."
            ),
        }
    ]
    inactive = detail_device()
    inactive["mac"] = "02:00:00:00:00:02"
    inactive["name"] = "Sensor antiguo"
    inactive["created"] = False
    inactive["enforcement"]["status"] = "inactive"

    second_active = detail_device()
    second_active["mac"] = "02:00:00:00:00:03"
    second_active["name"] = "Altavoz"
    second_active["observations"] = [
        {
            "id": "mdns",
            "label": "mDNS",
            "events": 1,
            "observed": True,
            "applied": False,
            "needs_authorization": True,
            "message": (
                "Este dispositivo necesita autorización para "
                "descubrimiento local mediante mDNS."
            ),
        }
    ]

    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal,
            "get_system_status",
            return_value={
                "dhcp": True,
                "discovery": True,
                "zeek": True,
                "wifi_isolation": True,
                "microsegmentation": True,
            },
        ),
        patch.object(
            setup_portal,
            "load_devices",
            return_value=[inactive, active, second_active],
        ),
    ):
        response = client.get("/dashboard")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "<h2>Estado general</h2>" in page
    assert '<p class="eyebrow">Estado general</p>' not in page
    assert "Resumen de dispositivos" in page
    assert "Dispositivos activos" in page
    assert "Dispositivos inactivos" in page
    assert page.index("Dispositivos activos") < page.index(
        "Dispositivos inactivos"
    )
    assert "1 dispositivo tiene una política pendiente en nftables." in page
    assert "Actividad Zeek parcial o no verificable en 1 dispositivo activo." in page
    assert "2 dispositivos necesitan autorización para descubrimiento local." in page
    assert (
        "Este dispositivo necesita autorización para descubrimiento local: SSDP."
        in page
    )
    assert (
        "Este dispositivo necesita autorización para descubrimiento local: mDNS."
        in page
    )
    assert "Limpiar dispositivos inactivos" in page


def test_dashboard_only_shows_protocols_with_observed_traffic():
    device = detail_device()
    device["activity"]["mdns_events"] = 5
    device["activity"]["ssdp_events"] = 3
    device["activity"]["broadcast_events"] = 0
    device["observations"] = setup_portal.build_protocol_observations(device)

    status, page = render_dashboard([device])

    assert status == 200
    assert device["activity"]["last_seen"] not in page
    assert "Muestra: 3 conexiones" in page
    chips_start = page.index('<div class="protocol-chips"')
    chips_end = page.index("</div>", chips_start)
    chips = page[chips_start:chips_end]
    assert chips.count('class="protocol-chip allowed"') == 1
    assert chips.count('class="protocol-chip observed"') == 1
    assert "mDNS / Bonjour" in chips
    assert "· 5" in chips
    assert "SSDP / UPnP" in chips
    assert "· 3" in chips
    assert "Broadcast" not in chips
    assert (
        "Este dispositivo necesita autorización para descubrimiento local: SSDP."
        in page
    )

    quiet_device = detail_device()
    quiet_device["activity"]["mdns_events"] = 0
    quiet_device["activity"]["ssdp_events"] = 0
    quiet_device["activity"]["broadcast_events"] = 0
    quiet_device["observations"] = setup_portal.build_protocol_observations(
        quiet_device
    )

    quiet_status, quiet_page = render_dashboard([quiet_device])

    assert quiet_status == 200
    assert 'aria-label="Protocolos detectados"' not in quiet_page


def test_device_api_returns_one_device_and_unknown_is_404():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal, "load_devices", return_value=[detail_device()]
        ),
    ):
        response = client.get("/api/devices/02:00:00:00:00:01")
        missing = client.get("/api/devices/02:00:00:00:00:ff")

    assert response.status_code == 200
    assert response.get_json()["device"]["name"] == "Televisor"
    assert missing.status_code == 404


def test_policy_post_from_detail_returns_to_same_device():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "actualizar_politica", return_value=True),
    ):
        response = client.post(
            "/devices/02:00:00:00:00:01/policy",
            data={"internet": "on", "broadcast": "block", "return_to": "detail"},
        )

    assert response.status_code == 302
    assert response.location.startswith("/devices/02:00:00:00:00:01?")


def test_alias_post_updates_separate_metadata_file():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "find_device", return_value=detail_device()),
        patch.object(setup_portal, "update_device_alias") as update,
    ):
        response = client.post(
            "/devices/02:00:00:00:00:01/name",
            data={"alias": "Televisor del salón"},
        )

    assert response.status_code == 302
    update.assert_called_once_with(
        "02:00:00:00:00:01",
        "Televisor del salón",
        setup_portal.DEVICE_METADATA_PATH,
    )
    assert "Alias+actualizado" in response.location


def test_device_inventory_includes_zeek_activity(tmp_path):
    database = tmp_path / "database.json"
    database.write_text(
        json.dumps(
            {
                "02:00:00:00:00:01": {
                    "ip_cliente": "192.168.10.100",
                    "ip_gateway": "192.168.10.1",
                    "creada": True,
                    "hostname": "living-room-tv",
                }
            }
        ),
        encoding="utf-8",
    )
    observed = {
        "last_seen": "2026-09-03 10:00:00 UTC",
        "last_seen_epoch": 1788429600.0,
        "recent": True,
        "connections": 1,
        "bytes_sent": 10,
        "bytes_received": 20,
        "destinations": ["203.0.113.8"],
        "dns_queries": [],
        "protocols": ["ssl"],
        "external_attempts": 1,
        "peer_flows": 0,
        "mdns_events": 0,
        "ssdp_events": 0,
        "broadcast_events": 0,
    }
    enforcement = {
        "status": "applied",
        "differences": [],
        "error": None,
        "controls": {},
    }
    with (
        patch.object(setup_portal, "DATABASE_PATH", database),
        patch.object(setup_portal, "ZEEK_LOG_DIR", tmp_path / "zeek"),
        patch.object(setup_portal, "obtener_politica", return_value={}),
        patch.object(
            setup_portal,
            "load_device_aliases",
            return_value={"02:00:00:00:00:01": "Televisor del salón"},
        ),
        patch.object(
            setup_portal,
            "load_device_activity",
            return_value={"02:00:00:00:00:01": observed},
        ) as activity_loader,
        patch.object(
            setup_portal,
            "load_policy_application",
            return_value={"02:00:00:00:00:01": enforcement},
        ) as policy_loader,
    ):
        devices = setup_portal.load_devices()

    assert devices[0]["activity"] == observed
    assert devices[0]["enforcement"] == enforcement
    assert devices[0]["name"] == "Televisor del salón"
    assert devices[0]["hostname"] == "living-room-tv"
    assert devices[0]["name_source"] == "alias"
    activity_loader.assert_called_once_with(devices, tmp_path / "zeek")
    policy_loader.assert_called_once_with(devices)


def test_device_name_falls_back_to_hostname_and_then_short_mac(tmp_path):
    database = tmp_path / "database.json"
    database.write_text(
        json.dumps(
            {
                "02:00:00:00:00:01": {"hostname": "sensor-kitchen"},
                "02:00:00:00:00:02": {},
            }
        ),
        encoding="utf-8",
    )
    activity = {"last_seen": None, "recent": False}
    with (
        patch.object(setup_portal, "DATABASE_PATH", database),
        patch.object(setup_portal, "load_device_aliases", return_value={}),
        patch.object(setup_portal, "obtener_politica", return_value={}),
        patch.object(
            setup_portal,
            "load_device_activity",
            return_value={
                "02:00:00:00:00:01": activity,
                "02:00:00:00:00:02": activity,
            },
        ),
        patch.object(
            setup_portal,
            "load_policy_application",
            return_value={
                "02:00:00:00:00:01": {},
                "02:00:00:00:00:02": {},
            },
        ),
    ):
        devices = setup_portal.load_devices()

    assert devices[0]["name"] == "sensor-kitchen"
    assert devices[0]["name_source"] == "dhcp"
    assert devices[1]["name"] == "Dispositivo 00:00:02"
    assert devices[1]["name_source"] == "generated"


def test_policy_post_persists_all_controls():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal, "actualizar_politica", return_value=True
        ) as update,
    ):
        response = client.post(
            "/devices/02:00:00:00:00:01/policy",
            data={
                "internet": "on",
                "mdns": "on",
                "broadcast": "on",
            },
        )

    assert response.status_code == 302
    update.assert_called_once_with(
        "02:00:00:00:00:01",
        internet=True,
        inter_device=False,
        mdns=True,
        ssdp=False,
        broadcast="allow",
    )


def test_policy_post_maps_unchecked_broadcast_to_block():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal, "actualizar_politica", return_value=True
        ) as update,
    ):
        response = client.post(
            "/devices/02:00:00:00:00:01/policy",
            data={"internet": "on"},
        )

    assert response.status_code == 302
    update.assert_called_once_with(
        "02:00:00:00:00:01",
        internet=True,
        inter_device=False,
        mdns=False,
        ssdp=False,
        broadcast="block",
    )


def test_legacy_broadcast_log_is_shown_as_enabled_and_allowed():
    device = detail_device()
    device["policy"]["inter_device"] = True
    device["policy"]["ssdp"] = True
    device["policy"]["broadcast"] = "log"
    device["enforcement"]["controls"]["broadcast"] = {
        "configured": "allow",
        "effective": "allow",
        "status": "applied",
    }
    device["observations"] = setup_portal.build_protocol_observations(device)
    device["trusted"] = setup_portal.is_device_trusted(device["policy"])

    dashboard_status, dashboard_page = render_dashboard([device])

    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "load_devices", return_value=[device]),
    ):
        response = client.get("/devices/02:00:00:00:00:01")

    page = response.get_data(as_text=True)
    assert dashboard_status == 200
    assert 'name="broadcast" checked' in dashboard_page
    assert 'select name="broadcast"' not in dashboard_page
    assert response.status_code == 200
    assert 'name="broadcast"' in page
    assert 'name="broadcast" aria-label="Permitir Broadcast" checked' in page
    assert 'select name="broadcast"' not in page
    assert '<fieldset class="policy-group">' not in page
    assert page.count('class="policy-table-toggle"') == 5
    assert "registrar y permitir" not in page
    assert setup_portal.format_policy_value("log") == "permitida"
    assert device["trusted"] is True


def test_invalid_setup_form_does_not_start_worker():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(setup_portal.threading, "Thread") as thread,
    ):
        response = client.post(
            "/setup",
            data={
                "router_brand": "unknown",
                "password": "admin",
                "ssid": "Home",
                "wifi_password": "wifi-password",
            },
        )

    assert response.status_code == 400
    thread.assert_not_called()


def test_setup_form_offers_adapter_detection_and_legacy_compatibility():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal,
            "discover_upstream_router",
            return_value=Mock(
                gateway="192.168.8.1",
                interface="eth0",
                base_url="http://192.168.8.1",
            ),
        ),
    ):
        response = client.get("/setup")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Detectar automáticamente" in page
    assert "Comprobar router sin modificarlo" in page
    assert "Mercusys / TP-Link (compatibilidad legacy)" in page
    assert 'value="http://192.168.8.1"' in page
    assert "192.168.8.1 por eth0" in page
    assert 'id="setup-form"' in page
    assert 'headers: {"Accept": "application/json"}' in page


def test_router_inspection_route_never_starts_migration_worker():
    inspection = RouterInspection(
        base_url="http://router.test",
        supported=True,
        adapter_id="glinet",
        maturity=AdapterMaturity.APPROVED,
        detection=DetectionResult(True, "glinet", confidence=0.9),
        capabilities=AdapterCapabilities(dhcp_status=False, disable_dhcp=False),
        status=RouterStatus(FeatureState.ENABLED, FeatureState.UNKNOWN),
        probes=(),
    )
    coordinator = Mock()
    coordinator.inspect.return_value = inspection
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "RouterCoordinator", return_value=coordinator
        ),
        patch.object(setup_portal.threading, "Thread") as thread,
    ):
        response = client.post(
            "/setup/router/inspect",
            data={
                "router_brand": "auto",
                "router_url": "http://router.test",
                "username": "root",
                "password": "admin",
                "ssid": "Home",
                "wifi_password": "wifi-password",
            },
        )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Router detectado: glinet" in page
    assert "Wi-Fi: enabled" in page
    assert "DHCP: unknown" not in page
    coordinator.inspect.assert_called_once_with(
        "http://router.test",
        Credentials(password="admin", username="root"),
        allow_experimental=False,
    )
    thread.assert_not_called()


def test_router_summary_tolerates_missing_dhcp_state():
    inspection = SimpleNamespace(
        adapter_id="router-without-dhcp",
        status=SimpleNamespace(
            wifi=SimpleNamespace(value="enabled"),
        ),
    )
    values = {
        "router_brand": "auto",
        "router_url": "http://router.test",
        "username": "",
        "ssid": "Home",
    }
    with (
        setup_portal.app.test_request_context("/setup"),
        patch.object(
            setup_portal, "discover_upstream_router", return_value=None
        ),
    ):
        page = setup_portal.render_setup(
            values=values,
            inspection=inspection,
        )

    assert "Router detectado: router-without-dhcp" in page
    assert "Wi-Fi: enabled" in page
    assert "DHCP: unknown" not in page


def test_router_inspection_json_keeps_credentials_out_of_response():
    inspection = RouterInspection(
        base_url="http://router.test",
        supported=True,
        adapter_id="mercusys-mr1500x",
        maturity=AdapterMaturity.EXPERIMENTAL,
        detection=DetectionResult(
            True, "mercusys-mr1500x", confidence=1.0
        ),
        capabilities=AdapterCapabilities(),
        status=RouterStatus(FeatureState.ENABLED, FeatureState.ENABLED),
        probes=(),
    )
    coordinator = Mock()
    coordinator.inspect.return_value = inspection
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "RouterCoordinator", return_value=coordinator
        ),
    ):
        response = client.post(
            "/setup/router/inspect",
            headers={"Accept": "application/json"},
            data={
                "router_brand": "mercusys_adapter",
                "router_url": "http://router.test",
                "username": "admin",
                "password": "router-secret",
                "ssid": "Home",
                "wifi_password": "wifi-secret",
            },
        )

    assert response.status_code == 200
    assert response.get_json() == {
        "ok": True,
        "adapter_id": "mercusys-mr1500x",
        "wifi": "enabled",
        "dhcp": "enabled",
    }
    assert b"router-secret" not in response.data
    assert b"wifi-secret" not in response.data

    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "RouterCoordinator", return_value=coordinator
        ),
    ):
        page_response = client.post(
            "/setup/router/inspect",
            data={
                "router_brand": "mercusys_adapter",
                "router_url": "http://router.test",
                "username": "admin",
                "password": "router-secret",
                "ssid": "Home",
                "wifi_password": "wifi-secret",
            },
        )

    assert page_response.status_code == 200
    assert "DHCP: enabled" in page_response.get_data(as_text=True)


def test_unknown_router_inspection_is_safe_and_explicit():
    inspection = RouterInspection(
        base_url="http://router.test",
        supported=False,
        adapter_id=None,
        maturity=None,
        detection=None,
        capabilities=None,
        status=None,
        probes=(),
    )
    coordinator = Mock()
    coordinator.inspect.return_value = inspection
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "RouterCoordinator", return_value=coordinator
        ),
    ):
        response = client.post(
            "/setup/router/inspect",
            data={
                "router_brand": "auto",
                "router_url": "http://router.test",
                "password": "admin",
                "ssid": "Home",
                "wifi_password": "wifi-password",
            },
        )

    assert response.status_code == 422
    page = response.get_data(as_text=True)
    assert "Router no compatible" in page
    assert "no se ha realizado ningún cambio" in page
    assert "Integrar este router con Codex" in page
    assert "Asistido con integraciones existentes (recomendado)" in page
    assert page.index('option value="assisted"') < page.index(
        'option value="clean_room"'
    )


def test_unknown_router_json_preserves_candidate_generation_flow():
    inspection = RouterInspection(
        base_url="http://router.test",
        supported=False,
        adapter_id=None,
        maturity=None,
        detection=None,
        capabilities=None,
        status=None,
        probes=(),
    )
    coordinator = Mock()
    coordinator.inspect.return_value = inspection
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(
            setup_portal, "RouterCoordinator", return_value=coordinator
        ),
    ):
        response = client.post(
            "/setup/router/inspect",
            headers={"Accept": "application/json"},
            data={
                "router_brand": "auto",
                "router_url": "http://router.test",
                "password": "router-secret",
                "ssid": "Home",
                "wifi_password": "wifi-secret",
            },
        )

    assert response.status_code == 422
    assert response.get_json()["unknown_router"] is True
    assert b"router-secret" not in response.data
    assert b"wifi-secret" not in response.data


def test_discovery_job_is_created_without_credentials_and_started_by_service(
    tmp_path,
):
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(setup_portal, "AI_STATE_DIR", tmp_path),
        patch.object(
            setup_portal,
            "AI_CREDENTIALS_DIR",
            tmp_path / "runtime-credentials",
        ),
        patch.object(setup_portal, "service_running", return_value=False),
        patch.object(setup_portal, "_command_ok", return_value=True) as command_ok,
        patch.object(setup_portal, "service_action", return_value=True) as service,
    ):
        response = client.post(
            "/setup/router/discovery",
                data={
                    "router_url": "http://router.test",
                    "mode": "assisted",
                    "password": "must-not-be-stored",
                    "ssid": "Original Home",
                    "wifi_password": "wifi-secret",
                },
        )

    assert response.status_code == 302
    job_id = response.location.rstrip("/").split("/")[-1]
    request_text = (
        tmp_path / "jobs" / job_id / "request.json"
    ).read_text(encoding="utf-8")
    assert "must-not-be-stored" not in request_text
    assert "password" not in request_text.lower()
    credentials_path = (
        tmp_path / "runtime-credentials" / f"{job_id}.json"
    )
    assert credentials_path.is_file()
    credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
    assert credentials["ssid"] == "Original Home"
    assert credentials["wifi_password"] == "wifi-secret"
    command_ok.assert_any_call(["uci", "set", f"tfg.ai.job_id={job_id}"])
    command_ok.assert_any_call(["uci", "commit", "tfg"])
    service.assert_called_once_with("tfg-ai-discovery", "start")


def test_discovery_status_endpoint_returns_persisted_state(tmp_path):
    job = setup_portal.create_job(
        "http://router.test",
        state_dir=tmp_path,
    )
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(setup_portal, "AI_STATE_DIR", tmp_path),
    ):
        response = client.get(
            f"/setup/discovery/{job['job_id']}/status"
        )

    assert response.status_code == 200
    assert response.get_json()["status"] == "pending"


def test_ready_candidate_migration_returns_to_standard_progress(tmp_path):
    job = setup_portal.create_job("http://router.test", state_dir=tmp_path)
    job_dir = tmp_path / "jobs" / job["job_id"]
    status = json.loads((job_dir / "status.json").read_text(encoding="utf-8"))
    status["status"] = "script_ready"
    (job_dir / "status.json").write_text(json.dumps(status), encoding="utf-8")
    worker = Mock()

    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=False),
        patch.object(setup_portal, "AI_STATE_DIR", tmp_path),
        patch.object(setup_portal.threading, "Thread", return_value=worker) as thread,
    ):
        response = client.post(
            f"/setup/discovery/{job['job_id']}/migrate",
            data={
                "username": "admin",
                "password": "router-secret",
                "ssid": "TFG Home",
                "wifi_password": "wifi-secret",
            },
        )

    assert response.status_code == 202
    assert b"Preparando la configuraci" in response.data
    thread.assert_called_once_with(
        target=setup_portal.finalize_script_takeover,
        args=("TFG Home", "wifi-secret"),
        daemon=True,
    )
    worker.start.assert_called_once_with()


def test_script_takeover_finishes_local_setup():
    with (
        patch.object(setup_portal, "complete_local_takeover") as complete_local,
        patch.object(setup_portal, "stop_normal_services"),
    ):
        assert setup_portal.finalize_script_takeover(
            "TFG Home", "wifi-secret"
        ) is True

    complete_local.assert_called_once_with("TFG Home", "wifi-secret")


def test_protocol_observations_keep_observed_desired_and_effective_separate():
    device = detail_device()
    device["activity"]["ssdp_events"] = 3

    observations = {
        item["id"]: item
        for item in setup_portal.build_protocol_observations(device)
    }

    assert observations["mdns"]["observed"] is True
    assert observations["mdns"]["authorized"] is True
    assert observations["mdns"]["applied"] is True
    assert observations["ssdp"]["observed"] is True
    assert observations["ssdp"]["authorized"] is False
    assert observations["ssdp"]["needs_authorization"] is True
    assert observations["ssdp"]["message"] == (
        "Este dispositivo necesita autorización para "
        "descubrimiento local mediante SSDP."
    )
    assert observations["broadcast"]["observed"] is False


def test_trust_button_enables_local_controls_without_changing_internet():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "find_device", return_value=detail_device()),
        patch.object(
            setup_portal, "actualizar_politica", return_value=True
        ) as update,
    ):
        response = client.post("/devices/02:00:00:00:00:01/trust")

    assert response.status_code == 302
    update.assert_called_once_with(
        "02:00:00:00:00:01",
        inter_device=True,
        mdns=True,
        ssdp=True,
        broadcast="allow",
    )
    assert "internet" not in update.call_args.kwargs


def test_trust_from_dashboard_redirects_back_to_dashboard():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "find_device", return_value=detail_device()),
        patch.object(setup_portal, "actualizar_politica", return_value=True),
    ):
        response = client.post(
            "/devices/02:00:00:00:00:01/trust",
            data={"return_to": "dashboard"},
        )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/dashboard?")
    assert "/devices/" not in response.headers["Location"]


def test_trust_button_restores_default_when_device_is_already_trusted():
    device = detail_device()
    device["policy"].update(
        {
            "inter_device": True,
            "mdns": True,
            "ssdp": True,
            "broadcast": "allow",
        }
    )
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(setup_portal, "find_device", return_value=device),
        patch.object(
            setup_portal, "restaurar_politica_por_defecto", return_value=True
        ) as reset,
        patch.object(setup_portal, "actualizar_politica") as update,
    ):
        response = client.post("/devices/02:00:00:00:00:01/trust")

    assert response.status_code == 302
    reset.assert_called_once_with("02:00:00:00:00:01")
    update.assert_not_called()
    assert "Confianza+retirada" in response.headers["Location"]


def test_cleanup_candidates_protect_runtime_and_existing_interfaces(tmp_path):
    removable = "02:00:00:00:00:01"
    runtime = "02:00:00:00:00:02"
    interface = "02:00:00:00:00:03"
    active = "02:00:00:00:00:04"
    (tmp_path / "v_present").mkdir()
    document = {
        removable: {"creada": False, "nombre_vlan": "v_missing"},
        runtime: {"creada": False, "nombre_vlan": "v_runtime"},
        interface: {"creada": False, "nombre_vlan": "v_present"},
        active: {"creada": True, "nombre_vlan": "v_active"},
    }

    candidates, protected = setup_portal._cleanup_candidates(
        document, {runtime}, sys_net=tmp_path
    )

    assert candidates == [removable]
    assert protected == [runtime, interface]


def test_cleanup_inactive_coordinates_service_and_metadata(tmp_path):
    inactive = "02:00:00:00:00:01"
    active = "02:00:00:00:00:02"
    database = tmp_path / "database.json"
    metadata = tmp_path / "aliases.json"
    database.write_text(
        json.dumps(
            {
                inactive: {"creada": False, "nombre_vlan": "v_inactive"},
                active: {"creada": True, "nombre_vlan": "v_active"},
            }
        ),
        encoding="utf-8",
    )
    metadata.write_text(
        json.dumps({inactive: "Antiguo", active: "Actual"}),
        encoding="utf-8",
    )

    with (
        patch.object(setup_portal, "DATABASE_PATH", database),
        patch.object(setup_portal, "DEVICE_METADATA_PATH", metadata),
        patch.object(setup_portal, "service_action", return_value=True) as stop,
        patch.object(
            setup_portal, "start_and_wait_for_service", return_value=True
        ) as start,
        patch.object(setup_portal, "_runtime_client_macs", return_value=set()),
        patch.object(
            setup_portal,
            "olvidar_politicas_dispositivos",
            return_value=True,
        ) as forget,
    ):
        result = setup_portal.cleanup_inactive_devices()

    assert result == {"removed": 1, "protected": 0}
    assert json.loads(database.read_text(encoding="utf-8")) == {
        active: {"creada": True, "nombre_vlan": "v_active"}
    }
    assert json.loads(metadata.read_text(encoding="utf-8")) == {
        active: "Actual"
    }
    stop.assert_called_once_with("tfg-dhcp", "stop")
    start.assert_called_once_with("tfg-dhcp")
    forget.assert_called_once_with([inactive])


def test_cleanup_restarts_dhcp_when_runtime_state_cannot_be_verified(tmp_path):
    database = tmp_path / "database.json"
    database.write_text(
        json.dumps(
            {"02:00:00:00:00:01": {"creada": False}}
        ),
        encoding="utf-8",
    )
    with (
        patch.object(setup_portal, "DATABASE_PATH", database),
        patch.object(setup_portal, "service_action", return_value=True),
        patch.object(setup_portal, "_runtime_client_macs", return_value=None),
        patch.object(
            setup_portal, "start_and_wait_for_service", return_value=True
        ) as start,
        pytest.raises(RuntimeError, match="nftables"),
    ):
        setup_portal.cleanup_inactive_devices()

    start.assert_called_once_with("tfg-dhcp")


def test_cleanup_route_reports_removed_and_protected_devices():
    with (
        setup_portal.app.test_client() as client,
        patch.object(setup_portal, "is_setup_complete", return_value=True),
        patch.object(
            setup_portal,
            "cleanup_inactive_devices",
            return_value={"removed": 2, "protected": 1},
        ) as cleanup,
    ):
        response = client.post("/devices/inactive/cleanup")

    assert response.status_code == 302
    assert "Se+eliminaron+2+dispositivo" in response.location
    assert "1+entrada" in response.location
    cleanup.assert_called_once_with()
