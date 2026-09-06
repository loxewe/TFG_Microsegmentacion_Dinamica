from unittest.mock import Mock

import pytest

from router_adapters import (
    AdapterCapabilities,
    AdapterMaturity,
    AdapterUnsupportedOperation,
    AdapterVerificationError,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RegistryDetection,
    RouterStatus,
    VerificationResult,
)
from router_integration import (
    RouterCoordinator,
    discover_upstream_router,
    normalize_router_url,
    parse_upstream_router,
)


def matched_report(adapter):
    detection = DetectionResult(True, adapter.adapter_id, confidence=0.9)
    return RegistryDetection(adapter, detection, ())


def adapter_mock(wifi=FeatureState.ENABLED):
    adapter = Mock()
    adapter.adapter_id = "fixture-router"
    adapter.maturity = AdapterMaturity.APPROVED
    adapter.capabilities = AdapterCapabilities()
    adapter.get_status.return_value = RouterStatus(
        wifi=wifi,
        dhcp=FeatureState.ENABLED,
    )
    adapter.disable_wifi.return_value = OperationResult(True, True)
    adapter.verify.return_value = VerificationResult(
        success=True,
        observed=RouterStatus(FeatureState.DISABLED, FeatureState.ENABLED),
        expected_wifi=FeatureState.DISABLED,
    )
    return adapter


def coordinator_for(report):
    registry = Mock()
    registry.detect_with_report.return_value = report
    return RouterCoordinator(registry)


def test_inspection_is_read_only_after_detection():
    adapter = adapter_mock()
    coordinator = coordinator_for(matched_report(adapter))

    result = coordinator.inspect(
        "http://router.test/",
        Credentials(password="fixture-password"),
    )

    assert result.supported is True
    assert result.base_url == "http://router.test"
    adapter.authenticate.assert_called_once()
    adapter.get_status.assert_called_once()
    adapter.disable_wifi.assert_not_called()
    adapter.disable_dhcp.assert_not_called()


def test_unknown_router_stops_without_authentication_or_writes():
    coordinator = coordinator_for(RegistryDetection(None, None, ()))

    result = coordinator.inspect(
        "http://router.test",
        Credentials(password="fixture-password"),
    )

    assert result.supported is False
    assert "no router change" in result.message
    with pytest.raises(AdapterUnsupportedOperation, match="no router change"):
        coordinator.disable_wifi(
            "http://router.test",
            Credentials(password="fixture-password"),
        )


def test_wifi_shutdown_uses_common_result_and_verifies_only_wifi():
    adapter = adapter_mock()
    coordinator = coordinator_for(matched_report(adapter))

    result = coordinator.disable_wifi(
        "http://router.test",
        Credentials(password="fixture-password"),
    )

    assert result.operation == OperationResult(True, True)
    adapter.disable_wifi.assert_called_once_with()
    adapter.verify.assert_called_once_with(wifi=FeatureState.DISABLED)


def test_already_disabled_wifi_is_not_written_again():
    adapter = adapter_mock(FeatureState.DISABLED)
    coordinator = coordinator_for(matched_report(adapter))

    result = coordinator.disable_wifi(
        "http://router.test",
        Credentials(password="fixture-password"),
    )

    assert result.operation.changed is False
    adapter.disable_wifi.assert_not_called()
    adapter.verify.assert_called_once_with(wifi=FeatureState.DISABLED)


def test_failed_post_write_verification_is_rejected():
    adapter = adapter_mock()
    adapter.verify.return_value = VerificationResult(
        success=False,
        observed=RouterStatus(FeatureState.ENABLED, FeatureState.ENABLED),
        expected_wifi=FeatureState.DISABLED,
    )
    coordinator = coordinator_for(matched_report(adapter))

    with pytest.raises(AdapterVerificationError, match="did not verify"):
        coordinator.disable_wifi(
            "http://router.test",
            Credentials(password="fixture-password"),
        )


@pytest.mark.parametrize(
    "value",
    ["router.test", "ftp://router.test", "http://user:pass@router.test"],
)
def test_router_url_rejects_unsafe_or_incomplete_values(value):
    with pytest.raises(ValueError):
        normalize_router_url(value)


def test_default_gateway_detection_selects_lowest_metric_private_route():
    route = parse_upstream_router(
        "default via 192.168.50.1 dev eth1 metric 200\n"
        "default via 192.168.8.1 dev eth0 src 192.168.8.116 metric 10\n"
    )

    assert route.gateway == "192.168.8.1"
    assert route.interface == "eth0"
    assert route.source == "192.168.8.116"
    assert route.base_url == "http://192.168.8.1"


def test_default_gateway_detection_rejects_public_gateway():
    assert parse_upstream_router("default via 8.8.8.8 dev eth0\n") is None


def test_upstream_discovery_does_not_scan_network(monkeypatch):
    completed = Mock(
        returncode=0,
        stdout="default via 192.168.8.1 dev eth0 metric 5\n",
    )
    run = Mock(return_value=completed)
    monkeypatch.setattr("router_integration.subprocess.run", run)

    route = discover_upstream_router()

    assert route.gateway == "192.168.8.1"
    run.assert_called_once_with(
        ["ip", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
