from unittest.mock import Mock, patch

import pytest

from router_adapters import AdapterProtocolError, Credentials, FeatureState
from router_adapters.adapters.xiaomi_r4cm import XiaomiR4CMAdapter


LOGIN_HTML = """
<title>MiWi-Fi Router</title>
<script>
var Encrypt = {key: 'fixture-key'};
var deviceId = 'fixture-device';
var PAGE_MONITOR_CONF = {
    romVersion: '3.0.45',
    romChannel: 'release',
    hardwareVersion: 'R4CM'
};
</script>
"""


def response(*, text="", payload=None):
    result = Mock()
    result.text = text
    result.json.return_value = payload
    result.raise_for_status.return_value = None
    return result


def adapter_with_session(base_url="http://router.test"):
    adapter = XiaomiR4CMAdapter(base_url)
    adapter.session = Mock()
    return adapter


def test_detection_reads_served_model_and_firmware():
    adapter = adapter_with_session()
    adapter.session.get.return_value = response(text=LOGIN_HTML)

    result = adapter.detect()

    assert result.applies is True
    assert result.variant == "R4CM"
    assert result.evidence["firmware"] == "3.0.45"
    assert adapter.session.get.call_args.args[0] == (
        "http://router.test/cgi-bin/luci/web"
    )


@patch("router_adapters.adapters.xiaomi_r4cm.time.time", return_value=1000)
@patch("router_adapters.adapters.xiaomi_r4cm.random.SystemRandom")
def test_authentication_uses_dynamic_page_metadata(system_random, _time):
    system_random.return_value.randrange.return_value = 7
    adapter = adapter_with_session()
    adapter.session.get.return_value = response(text=LOGIN_HTML)
    adapter.session.post.return_value = response(
        payload={"code": 0, "token": "fixture-session"}
    )

    adapter.authenticate(Credentials(username="admin", password="fixture-password"))

    call = adapter.session.post.call_args
    assert call.args[0] == "http://router.test/cgi-bin/luci/api/xqsystem/login"
    assert call.kwargs["data"] == {
        "username": "admin",
        "password": XiaomiR4CMAdapter._digest(
            "fixture-password", "0_fixture-device_1000_7", "fixture-key"
        ),
        "logtype": "2",
        "nonce": "0_fixture-device_1000_7",
    }


def test_status_reads_wifi_and_dhcp():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.side_effect = [
        response(payload={"code": 0, "info": [{"status": "1"}, {"status": 0}]}),
        response(payload={"code": 0, "info": {"ignore": "0"}}),
    ]

    status = adapter.get_status()

    assert status.wifi is FeatureState.ENABLED
    assert status.dhcp is FeatureState.ENABLED
    assert status.details == {
        "wifi_radio_statuses": ["1", 0],
        "dhcp_ignore": "0",
    }


def test_disable_dhcp_uses_only_ignore_flag():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.return_value = response(payload={"code": 0})

    result = adapter.disable_dhcp()

    assert result.success is True
    assert result.changed is True
    call = adapter.session.get.call_args
    assert call.args[0].endswith("/api/xqnetwork/set_lan_dhcp")
    assert call.kwargs["params"] == {"ignore": "1"}


def test_verify_performs_new_status_reads():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.side_effect = [
        response(payload={"code": 0, "info": [{"status": 0}]}),
        response(payload={"code": 0, "info": {"ignore": "1"}}),
    ]

    result = adapter.verify(
        wifi=FeatureState.DISABLED,
        dhcp=FeatureState.DISABLED,
    )

    assert result.success is True
    assert adapter.session.get.call_count == 2


@pytest.mark.parametrize(
    ("wifi_response", "dhcp_response"),
    [
        ({"code": 0, "info": "unexpected"}, {"code": 0, "info": {}}),
        ({"code": 0, "info": [{"status": "unexpected"}]}, {"code": 0}),
    ],
)
def test_unexpected_status_responses_are_unknown(wifi_response, dhcp_response):
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.side_effect = [
        response(payload=wifi_response),
        response(payload=dhcp_response),
    ]

    status = adapter.get_status()

    assert status.wifi is FeatureState.UNKNOWN
    assert status.dhcp is FeatureState.UNKNOWN


def primary_wifi(status="1"):
    return {
        "code": 0,
        "info": [
            {
                "status": status,
                "ssid": "fixture-ssid",
                "password": "fixture&amp;password",
                "encryption": "psk2",
                "channel": "6",
                "bandwidth": "20",
                "hidden": "0",
                "txpwr": "max",
            }
        ],
    }


def test_disable_wifi_preserves_full_config_and_verifies_primary_radio():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.side_effect = [
        response(payload=primary_wifi()),  # preview
        response(payload=primary_wifi()),  # immediate pre-write read
    ]
    adapter.session.post.return_value = response(payload={"code": 0})
    adapter._wait_for_primary_wifi = Mock(return_value=FeatureState.DISABLED)

    preview = adapter.plan_disable_wifi()
    result = adapter.disable_wifi()

    assert result.success is True
    assert result.changed is True
    assert result.details == {"primary_2g": "disabled"}
    assert adapter.sanitize_wifi_payload(preview) == {
        "wifiIndex": "1",
        "on": "0",
        "ssid": "<REDACTED:PRESERVED>",
        "pwd": "<REDACTED:PRESERVED_AND_PWDDECODED>",
        "encryption": "psk2",
        "channel": "6",
        "bandwidth": "20",
        "hidden": "0",
        "txpwr": "max",
    }
    posted = adapter.session.post.call_args.kwargs["data"]
    assert posted == {
        "wifiIndex": "1",
        "on": "0",
        "ssid": "fixture-ssid",
        "pwd": "fixture&password",
        "encryption": "psk2",
        "channel": "6",
        "bandwidth": "20",
        "hidden": "0",
        "txpwr": "max",
    }


def test_disable_wifi_rolls_back_and_verifies_on_failed_verify():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    adapter.session.get.side_effect = [
        response(payload=primary_wifi()),
        response(payload=primary_wifi()),
    ]
    adapter.session.post.return_value = response(payload={"code": 0})
    adapter._wait_for_primary_wifi = Mock(
        side_effect=[FeatureState.ENABLED, FeatureState.ENABLED]
    )

    adapter.plan_disable_wifi()
    with pytest.raises(AdapterProtocolError, match="restored and verified"):
        adapter.disable_wifi()

    assert adapter.session.post.call_count == 2
    rollback = adapter.session.post.call_args.kwargs["data"]
    assert rollback["on"] == "1"


@patch("router_adapters.adapters.xiaomi_r4cm.time.sleep")
@patch("router_adapters.adapters.xiaomi_r4cm.time.monotonic")
def test_wifi_verify_waits_for_ui_settle_period(monotonic, sleep):
    adapter = XiaomiR4CMAdapter()
    adapter._primary_wifi_state = Mock(return_value=FeatureState.DISABLED)
    monotonic.side_effect = [100.0, 100.0]

    observed = adapter._wait_for_primary_wifi(FeatureState.DISABLED)

    assert observed is FeatureState.DISABLED
    sleep.assert_called_once_with(30.0)


def test_disable_wifi_aborts_if_config_changed_after_preview():
    adapter = adapter_with_session()
    adapter._token = "fixture-session"
    changed = primary_wifi()
    changed["info"][0]["channel"] = "11"
    adapter.session.get.side_effect = [
        response(payload=primary_wifi()),
        response(payload=changed),
    ]

    adapter.plan_disable_wifi()
    with pytest.raises(AdapterProtocolError, match="changed after preview"):
        adapter.disable_wifi()

    adapter.session.post.assert_not_called()
