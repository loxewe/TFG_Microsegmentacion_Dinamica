"""Application-facing orchestration for domestic-router adapters.

This module does not participate in SETUP yet. It provides the deterministic
boundary that the portal can call after read-only hardware validation.
"""

from dataclasses import dataclass
import ipaddress
import subprocess
from typing import Optional, Tuple
from urllib.parse import urlsplit

from router_adapters import (
    AdapterCapabilities,
    AdapterMaturity,
    AdapterProbe,
    AdapterProtocolError,
    AdapterRegistry,
    AdapterUnsupportedOperation,
    AdapterVerificationError,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RegistryDetection,
    RouterStatus,
    VerificationResult,
    create_default_registry,
)


@dataclass(frozen=True)
class RouterInspection:
    base_url: str
    supported: bool
    adapter_id: Optional[str]
    maturity: Optional[AdapterMaturity]
    detection: Optional[DetectionResult]
    capabilities: Optional[AdapterCapabilities]
    status: Optional[RouterStatus]
    probes: Tuple[AdapterProbe, ...]
    message: str = ""


@dataclass(frozen=True)
class WifiDisableResult:
    adapter_id: str
    before: RouterStatus
    operation: OperationResult
    verification: VerificationResult


@dataclass(frozen=True)
class UpstreamRouter:
    gateway: str
    interface: Optional[str]
    source: Optional[str]
    metric: int

    @property
    def base_url(self) -> str:
        return f"http://{self.gateway}"


LOCAL_GATEWAY_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
    )
)


def parse_upstream_router(route_output: str) -> Optional[UpstreamRouter]:
    """Select the lowest-metric local IPv4 default gateway."""
    candidates = []
    for line in route_output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default" or "via" not in fields:
            continue
        try:
            gateway_text = fields[fields.index("via") + 1]
            gateway = ipaddress.ip_address(gateway_text)
        except (ValueError, IndexError):
            continue
        if gateway.version != 4 or not any(
            gateway in network for network in LOCAL_GATEWAY_NETWORKS
        ):
            continue

        interface = None
        source = None
        metric = 0
        try:
            interface = fields[fields.index("dev") + 1]
        except (ValueError, IndexError):
            pass
        try:
            source = fields[fields.index("src") + 1]
        except (ValueError, IndexError):
            pass
        try:
            metric = int(fields[fields.index("metric") + 1])
        except (ValueError, IndexError):
            pass
        candidates.append(
            UpstreamRouter(str(gateway), interface, source, metric)
        )

    if not candidates:
        return None
    return min(candidates, key=lambda route: route.metric)


def discover_upstream_router() -> Optional[UpstreamRouter]:
    """Read the Raspberry Pi route table without sending network traffic."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return parse_upstream_router(result.stdout)


def normalize_router_url(base_url: str) -> str:
    value = (base_url or "").strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("router URL must include http:// or https:// and a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("router URL must not contain credentials, query or fragment")
    return value


class RouterCoordinator:
    def __init__(self, registry: Optional[AdapterRegistry] = None):
        self.registry = registry or create_default_registry()

    def detect(
        self,
        base_url: str,
        *,
        allow_experimental: bool = False,
    ) -> RegistryDetection:
        return self.registry.detect_with_report(
            normalize_router_url(base_url),
            allow_experimental=allow_experimental,
        )

    def inspect(
        self,
        base_url: str,
        credentials: Credentials,
        *,
        allow_experimental: bool = False,
    ) -> RouterInspection:
        normalized_url = normalize_router_url(base_url)
        report = self.registry.detect_with_report(
            normalized_url,
            allow_experimental=allow_experimental,
        )
        if report.adapter is None:
            return RouterInspection(
                base_url=normalized_url,
                supported=False,
                adapter_id=None,
                maturity=None,
                detection=None,
                capabilities=None,
                status=None,
                probes=report.probes,
                message="no approved adapter matched; no router change was made",
            )

        adapter = report.adapter
        adapter.authenticate(credentials)
        status = adapter.get_status()
        return RouterInspection(
            base_url=normalized_url,
            supported=True,
            adapter_id=adapter.adapter_id,
            maturity=adapter.maturity,
            detection=report.detection,
            capabilities=adapter.capabilities,
            status=status,
            probes=report.probes,
            message="router detected and inspected without configuration writes",
        )

    def disable_wifi(
        self,
        base_url: str,
        credentials: Credentials,
        *,
        allow_experimental: bool = False,
    ) -> WifiDisableResult:
        report = self.detect(
            base_url,
            allow_experimental=allow_experimental,
        )
        return self.disable_detected_wifi(report, credentials)

    def disable_detected_wifi(
        self,
        report: RegistryDetection,
        credentials: Credentials,
    ) -> WifiDisableResult:
        if report.adapter is None:
            raise AdapterUnsupportedOperation(
                "no approved adapter matched; no router change was made"
            )

        adapter = report.adapter
        if not adapter.capabilities.disable_wifi:
            raise AdapterUnsupportedOperation(
                f"{adapter.adapter_id} does not support Wi-Fi shutdown"
            )

        adapter.authenticate(credentials)
        before = adapter.get_status()
        if before.wifi is FeatureState.DISABLED:
            operation = OperationResult(
                success=True,
                changed=False,
                message="Wi-Fi was already disabled",
            )
        else:
            operation = adapter.disable_wifi()
            if not operation.success:
                raise AdapterProtocolError(
                    f"{adapter.adapter_id} did not confirm the Wi-Fi write"
                )

        verification = adapter.verify(wifi=FeatureState.DISABLED)
        if not verification.success:
            raise AdapterVerificationError(
                f"{adapter.adapter_id} did not verify Wi-Fi as disabled"
            )

        return WifiDisableResult(
            adapter_id=adapter.adapter_id,
            before=before,
            operation=operation,
            verification=verification,
        )


def inspect_router(
    base_url: str,
    credentials: Credentials,
    *,
    allow_experimental: bool = False,
) -> RouterInspection:
    return RouterCoordinator().inspect(
        base_url,
        credentials,
        allow_experimental=allow_experimental,
    )
