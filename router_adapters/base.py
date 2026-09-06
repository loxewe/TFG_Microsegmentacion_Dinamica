"""Minimal contract implemented by every router/firmware adapter."""

from abc import ABC, abstractmethod
from typing import Optional

from .models import (
    AdapterCapabilities,
    AdapterMaturity,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterStatus,
    VerificationResult,
)


class RouterAdapter(ABC):
    """
    A stateful integration with one router.

    Implementations may freely keep cookies, tokens, cryptographic state or a
    firmware-specific navigation context. None of those details are part of the
    public contract.
    """

    adapter_id = "unknown"
    capabilities = AdapterCapabilities()
    maturity = AdapterMaturity.EXPERIMENTAL

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    @abstractmethod
    def detect(self) -> DetectionResult:
        """Probe without credentials and report whether this adapter applies."""

    @abstractmethod
    def authenticate(self, credentials: Credentials) -> None:
        """Create the firmware-specific authenticated context."""

    @abstractmethod
    def get_status(self) -> RouterStatus:
        """Return Wi-Fi and DHCP state; UNKNOWN is valid when unavailable."""

    @abstractmethod
    def disable_wifi(self) -> OperationResult:
        """Request Wi-Fi shutdown or raise an AdapterError."""

    @abstractmethod
    def disable_dhcp(self) -> OperationResult:
        """Request DHCP shutdown or raise AdapterUnsupportedOperation."""

    def verify(
        self,
        *,
        wifi: Optional[FeatureState] = None,
        dhcp: Optional[FeatureState] = None,
    ) -> VerificationResult:
        """Read state again and compare only the requested expectations."""
        observed = self.get_status()
        matches = []
        if wifi is not None:
            matches.append(observed.wifi == wifi)
        if dhcp is not None:
            matches.append(observed.dhcp == dhcp)
        success = bool(matches) and all(matches)
        return VerificationResult(
            success=success,
            observed=observed,
            expected_wifi=wifi,
            expected_dhcp=dhcp,
            message="verified" if success else "observed state does not match",
        )
