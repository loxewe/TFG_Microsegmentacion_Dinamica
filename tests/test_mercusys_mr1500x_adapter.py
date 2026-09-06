import json
from unittest.mock import Mock, patch

from router_adapters import Credentials, FeatureState
from router_adapters.adapters import MercusysMR1500XAdapter


def response(payload):
    value = Mock()
    value.json.return_value = payload
    value.raise_for_status.return_value = None
    return value


def public_api(form):
    values = {
        "/login?form=get_deviceInfo": {
            "success": True,
            "data": {"model": "MR1500X"},
        },
        "/login?form=get_firmware_info": {
            "success": True,
            "data": {
                "model": "MR1500X",
                "hardware_version": "MR1500X v2.0",
                "firmware_version": "test-firmware",
            },
        },
        "/login?form=keys": {
            "success": True,
            "data": {"password": ["password-modulus", "010001"]},
        },
        "/login?form=auth": {
            "success": True,
            "data": {"key": ["signature-modulus", "010001"], "seq": 10},
        },
    }
    return values[form]


def wifi_state(value="off"):
    return {
        "success": True,
        "data": {
            "wireless_2g_enable": value,
            "wireless_5g_enable": value,
            "wireless_2g_disabled_all": "on" if value == "off" else "off",
            "wireless_5g_disabled_all": "on" if value == "off" else "off",
            "wireless_2g_hwmode": "bgn",
            "wireless_2g_htmode": "auto",
            "wireless_2g_channel": "auto",
            "wireless_2g_txpower": "high",
            "wireless_5g_hwmode": "anacax_5",
            "wireless_5g_htmode": "80",
            "wireless_5g_channel": "auto",
            "wireless_5g_txpower": "high",
            "wireless_5g_mu_mimo": "on",
            "wireless_2g_psk_key": "must-not-leak",
        },
    }


def dhcp_state(value="on"):
    return {
        "success": True,
        "data": {
            "enable": value,
            "domain": "",
            "gateway": "192.0.2.1",
            "ipaddr_start": "192.0.2.100",
            "ipaddr_end": "192.0.2.200",
            "leasetime": "120",
            "pri_dns": "",
            "snd_dns": "",
        },
    }


def authenticate(adapter):
    adapter._public_read = Mock(side_effect=public_api)
    adapter.session = Mock()
    adapter.session.post.return_value = response({"data": "login-response"})
    with (
        patch(
            "router_adapters.adapters.mercusys_mr1500x._rsa_chunks",
            return_value="rsa-value",
        ),
        patch.object(adapter, "_aes_encrypt", return_value="aes-value"),
        patch.object(
            adapter,
            "_aes_decrypt",
            return_value=json.dumps({"data": {"stok": "test-session"}}),
        ),
    ):
        adapter.authenticate(Credentials(password="test-password"))


def test_generated_adapter_complete_success_flow():
    adapter = MercusysMR1500XAdapter("http://192.0.2.1")
    adapter._public_read = Mock(side_effect=public_api)

    detection = adapter.detect()

    assert detection.applies is True
    assert detection.variant == "MR1500X v2.0"

    authenticate(adapter)
    adapter._read_wifi = Mock(side_effect=[wifi_state(), wifi_state(), wifi_state()])
    adapter._read_dhcp = Mock(
        side_effect=[dhcp_state("on"), dhcp_state("on"), dhcp_state("off")]
    )
    adapter._write_operation = Mock(return_value={"success": True})

    initial = adapter.get_status()
    wifi_result = adapter.disable_wifi()
    dhcp_result = adapter.disable_dhcp()
    verification = adapter.verify(dhcp=FeatureState.DISABLED)

    assert initial.wifi is FeatureState.DISABLED
    assert initial.dhcp is FeatureState.ENABLED
    assert initial.details == {"wifi_2g": "off", "wifi_5g": "off", "dhcp": "on"}
    assert "must-not-leak" not in repr(initial)
    assert wifi_result.success is True
    assert wifi_result.changed is False
    assert wifi_result.message == "already disabled"
    assert dhcp_result.success is True
    assert dhcp_result.changed is True
    assert verification.success is True
    assert verification.observed.dhcp is FeatureState.DISABLED

    adapter._write_operation.assert_called_once()
    path, payload = adapter._write_operation.call_args.args
    assert path.endswith("/admin/dhcps?form=setting")
    assert payload["enable"] == "off"
    previous = adapter._dhcp_restore_payload
    assert previous["enable"] == "on"
    assert {
        key: value for key, value in payload.items() if key != "enable"
    } == {key: value for key, value in previous.items() if key != "enable"}


def test_wifi_write_uses_only_the_firmware_writable_fields():
    adapter = MercusysMR1500XAdapter("http://192.0.2.1")
    adapter._read_wifi = Mock(return_value=wifi_state("on"))
    adapter._write_operation = Mock(return_value={"success": True})

    result = adapter.disable_wifi()

    assert result.success is True
    path, payload = adapter._write_operation.call_args.args
    assert path.endswith("/admin/wireless?form=wireless_2g&form=wireless_5g")
    assert payload["operation"] == "write_spf"
    assert payload["wireless_2g_enable"] == "off"
    assert payload["wireless_2g_disabled_all"] == "on"
    assert payload["wireless_5g_enable"] == "off"
    assert payload["wireless_5g_disabled_all"] == "on"
    assert payload["wireless_2g_transmitPowerDisable"] == ""
    assert payload["wireless_5g_transmitPowerDisable"] == ""
    assert "wireless_2g_psk_key" not in payload


def test_failed_verification_uses_exact_dhcp_snapshot_for_rollback():
    adapter = MercusysMR1500XAdapter("http://192.0.2.1")
    adapter._stok = "test-session"
    before = dhcp_state("on")
    adapter._read_dhcp = Mock(side_effect=[before, before, before])
    adapter._read_wifi = Mock(side_effect=[wifi_state(), wifi_state()])
    adapter._write_operation = Mock(return_value={"success": True})

    adapter.disable_dhcp()
    verification = adapter.verify(dhcp=FeatureState.DISABLED)
    assert verification.success is False

    rollback = adapter.restore_dhcp()
    restored = adapter.get_status()

    assert rollback == {"success": True, "restored": True}
    assert restored.dhcp is FeatureState.ENABLED
    assert adapter._write_operation.call_count == 2
    disable_call, restore_call = adapter._write_operation.call_args_list
    assert disable_call.args[1]["enable"] == "off"
    assert restore_call.args == (
        disable_call.args[0],
        {"operation": "write", **before["data"]},
    )


def test_verify_checks_only_the_requested_feature():
    adapter = MercusysMR1500XAdapter("http://192.0.2.1")
    adapter._read_wifi = Mock(return_value=wifi_state("off"))
    adapter._read_dhcp = Mock(return_value=dhcp_state("on"))

    verification = adapter.verify(wifi=FeatureState.DISABLED)

    assert verification.success is True
    assert verification.expected_wifi is FeatureState.DISABLED
    assert verification.expected_dhcp is None
