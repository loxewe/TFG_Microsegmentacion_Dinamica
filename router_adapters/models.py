"""Protocol-independent values exchanged with router adapters."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class FeatureState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class AdapterMaturity(str, Enum):
    APPROVED = "approved"
    EXPERIMENTAL = "experimental"
    DISABLED = "disabled"


@dataclass(frozen=True)
class Credentials:
    password: str
    username: Optional[str] = None
    extras: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterCapabilities:
    wifi_status: bool = True
    dhcp_status: bool = True
    disable_wifi: bool = True
    disable_dhcp: bool = True


@dataclass(frozen=True)
class DetectionResult:
    applies: bool
    adapter: str
    variant: Optional[str] = None
    confidence: float = 0.0
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RouterStatus:
    wifi: FeatureState
    dhcp: FeatureState
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    success: bool
    observed: RouterStatus
    expected_wifi: Optional[FeatureState] = None
    expected_dhcp: Optional[FeatureState] = None
    message: str = ""


@dataclass(frozen=True)
class OperationResult:
    success: bool
    changed: bool
    message: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
