"""Adapters backed by executable scripts generated during router discovery."""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple, Type

from .base import RouterAdapter
from .errors import AdapterAuthenticationError, AdapterProtocolError, AdapterUnsupportedOperation
from .models import (
    AdapterCapabilities,
    AdapterMaturity,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterStatus,
)


DEFAULT_INTEGRATIONS_DIR = Path("/etc/tfg-ai/integrations")


def run_script_command(
    script: Path,
    action: str,
    base_url: str,
    credentials: Optional[Credentials] = None,
    timeout: int = 90,
) -> Dict:
    """Run the small JSON protocol without exposing credentials in argv."""
    payload = ""
    if credentials is not None:
        payload = json.dumps(
            {"username": credentials.username, "password": credentials.password}
        )
    try:
        result = subprocess.run(
            ["python3", str(script), action, "--base-url", base_url],
            input=payload,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AdapterProtocolError(str(error)) from error
    if result.returncode != 0:
        detail = result.stderr.strip() or "script returned a non-zero status"
        raise AdapterProtocolError(detail)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise AdapterProtocolError("script returned no JSON result")
    try:
        document = json.loads(lines[-1])
    except ValueError as error:
        raise AdapterProtocolError("script returned invalid JSON") from error
    if not isinstance(document, dict):
        raise AdapterProtocolError("script result must be a JSON object")
    return document


def _feature(value) -> FeatureState:
    try:
        return FeatureState(value)
    except ValueError:
        return FeatureState.UNKNOWN


def build_script_adapter_type(entry: Dict, integrations_dir: Path) -> Type[RouterAdapter]:
    script = integrations_dir / entry["file"]
    integration_id = entry["integration_id"]

    class GeneratedScriptAdapter(RouterAdapter):
        adapter_id = integration_id
        maturity = AdapterMaturity.APPROVED
        capabilities = AdapterCapabilities(
            wifi_status=True,
            dhcp_status=bool(entry.get("dhcp_status", False)),
            disable_wifi=True,
            disable_dhcp=False,
        )
        _script = script

        def __init__(self, base_url: str):
            super().__init__(base_url)
            self._credentials = None

        def detect(self) -> DetectionResult:
            result = run_script_command(self._script, "detect", self.base_url)
            if result.get("integration_id") != self.adapter_id:
                raise AdapterProtocolError("script returned a different integration_id")
            return DetectionResult(
                applies=bool(result.get("applies")),
                adapter=self.adapter_id,
                variant=result.get("variant"),
                confidence=float(result.get("confidence", 0.0)),
                evidence=result.get("evidence") or {},
            )

        def authenticate(self, credentials: Credentials) -> None:
            self._credentials = credentials
            result = run_script_command(
                self._script, "status", self.base_url, credentials
            )
            if not result.get("success", False):
                self._credentials = None
                raise AdapterAuthenticationError(
                    result.get("error") or "script authentication failed"
                )

        def get_status(self) -> RouterStatus:
            if self._credentials is None:
                raise AdapterAuthenticationError("script is not authenticated")
            result = run_script_command(
                self._script, "status", self.base_url, self._credentials
            )
            if not result.get("success", False):
                raise AdapterProtocolError(result.get("error") or "status failed")
            return RouterStatus(
                wifi=_feature(result.get("wifi")),
                dhcp=_feature(result.get("dhcp")),
                details=result.get("details") or {},
            )

        def disable_wifi(self) -> OperationResult:
            if self._credentials is None:
                raise AdapterAuthenticationError("script is not authenticated")
            result = run_script_command(
                self._script, "off", self.base_url, self._credentials
            )
            return OperationResult(
                success=bool(result.get("success")),
                changed=bool(result.get("changed", True)),
                message=result.get("message", ""),
                details=result.get("details") or {},
            )

        def disable_dhcp(self) -> OperationResult:
            raise AdapterUnsupportedOperation("generated scripts do not modify DHCP")

    GeneratedScriptAdapter.__name__ = "GeneratedScript_" + integration_id.replace("-", "_")
    return GeneratedScriptAdapter


def load_script_adapter_types(
    integrations_dir: Path = DEFAULT_INTEGRATIONS_DIR,
) -> Tuple[Type[RouterAdapter], ...]:
    """Load hash-verified executable integrations from their manifest."""
    integrations_dir = Path(integrations_dir)
    manifest_path = integrations_dir / "manifest.json"
    if not manifest_path.is_file():
        return ()
    try:
        entries = json.loads(manifest_path.read_text(encoding="utf-8"))["integrations"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return ()
    loaded = []
    for entry in entries:
        try:
            filename = entry["file"]
            if Path(filename).name != filename:
                continue
            content = (integrations_dir / filename).read_bytes()
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                continue
            loaded.append(build_script_adapter_type(entry, integrations_dir))
        except (KeyError, OSError, TypeError, ValueError):
            continue
    return tuple(loaded)
