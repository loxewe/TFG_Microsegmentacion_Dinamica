"""Public API for domestic-router integrations."""

from .base import RouterAdapter
from .errors import (
    AdapterAuthenticationError,
    AdapterError,
    AdapterProtocolError,
    AdapterUnsupportedOperation,
    AdapterVerificationError,
)
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
from .registry import (
    AdapterProbe,
    AdapterRegistry,
    RegistryDetection,
    create_default_registry,
    load_approved_adapter_types,
)
from .script_adapter import load_script_adapter_types, run_script_command

__all__ = [
    "AdapterAuthenticationError",
    "AdapterCapabilities",
    "AdapterError",
    "AdapterMaturity",
    "AdapterProbe",
    "AdapterProtocolError",
    "AdapterRegistry",
    "AdapterUnsupportedOperation",
    "AdapterVerificationError",
    "Credentials",
    "DetectionResult",
    "FeatureState",
    "OperationResult",
    "RegistryDetection",
    "RouterAdapter",
    "RouterStatus",
    "VerificationResult",
    "create_default_registry",
    "load_approved_adapter_types",
    "load_script_adapter_types",
    "run_script_command",
]
