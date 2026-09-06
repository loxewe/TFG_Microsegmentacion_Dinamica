from unittest.mock import Mock

import pytest
import requests

from router_adapters import (
    AdapterUnsupportedOperation,
    Credentials,
    FeatureState,
)
from router_adapters.adapters import GLInetAdapter


def rpc_response(payload):
    response = Mock()
    response.json.return_value = payload
    return response


def mock_session(adapter):
    adapter.session = Mock()
    adapter.session.cookies = Mock()
    return adapter.session


def test_glinet_detection_uses_public_challenge():
    adapter = GLInetAdapter()
    session = mock_session(adapter)
    session.post.return_value = rpc_response(
        {"result": {"nonce": "n", "salt": "12345678"}}
    )

    result = adapter.detect()

    assert result.applies is True
    payload = adapter.session.post.call_args.kwargs["json"]
    assert payload["method"] == "challenge"
    assert payload["params"] == {"username": "root"}


def test_glinet_migrated_wifi_shutdown_payload():
    adapter = GLInetAdapter()
    session = mock_session(adapter)
    session.post.side_effect = [
        rpc_response({"result": {"nonce": "n", "salt": "12345678"}}),
        rpc_response({"result": {"sid": "test-sid"}}),
        rpc_response({"result": {}}),
    ]

    adapter.authenticate(Credentials(password="secret"))
    adapter.disable_wifi()

    payload = adapter.session.post.call_args.kwargs["json"]
    assert payload["method"] == "call"
    assert payload["params"] == [
        "test-sid",
        "wifi",
        "set_config",
        {"iface_name": "wifi2g", "enabled": False},
    ]


def test_glinet_status_and_common_verification():
    adapter = GLInetAdapter()
    session = mock_session(adapter)
    adapter._sid = "test-sid"
    session.post.return_value = rpc_response(
        {"result": {"enabled": False}}
    )

    result = adapter.verify(wifi=FeatureState.DISABLED)

    assert result.success is True
    assert result.observed.dhcp is FeatureState.UNKNOWN


def test_glinet_status_reads_nested_iface_without_exposing_wifi_key():
    adapter = GLInetAdapter()
    session = mock_session(adapter)
    adapter._sid = "test-sid"
    session.post.return_value = rpc_response(
        {
            "result": {
                "res": [
                    {
                        "band": "2G",
                        "ifaces": [
                            {
                                "name": "wifi2g",
                                "guest": False,
                                "enabled": True,
                                "ssid": "Synthetic-Network",
                                "key": "synthetic-secret",
                            },
                            {
                                "name": "guest2g",
                                "guest": True,
                                "enabled": False,
                            },
                        ],
                    }
                ]
            }
        }
    )

    status = adapter.get_status()

    assert status.wifi is FeatureState.ENABLED
    assert status.details == {"wifi2g": {"enabled": True}}
    assert "synthetic-secret" not in repr(status.details)


def test_glinet_disconnect_during_shutdown_preserves_switcher_semantics():
    adapter = GLInetAdapter()
    session = mock_session(adapter)
    adapter._sid = "test-sid"
    session.post.side_effect = requests.ConnectionError("radio went away")

    adapter.disable_wifi()


def test_unmapped_glinet_dhcp_is_explicit():
    adapter = GLInetAdapter()
    with pytest.raises(AdapterUnsupportedOperation):
        adapter.disable_dhcp()
