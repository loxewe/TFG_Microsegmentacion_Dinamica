"""Explicit, side-effect-free registry construction and adapter discovery."""

from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import time
from typing import Iterable, List, Optional, Tuple, Type

from .base import RouterAdapter
from .errors import AdapterError
from .models import AdapterMaturity, DetectionResult


@dataclass(frozen=True)
class AdapterProbe:
    adapter_id: str
    maturity: AdapterMaturity
    result: Optional[DetectionResult] = None
    error: Optional[str] = None
    skipped: bool = False


@dataclass(frozen=True)
class RegistryDetection:
    adapter: Optional[RouterAdapter]
    detection: Optional[DetectionResult]
    probes: Tuple[AdapterProbe, ...]

    @property
    def supported(self) -> bool:
        return self.adapter is not None


class AdapterRegistry:
    def __init__(
        self,
        adapter_types: Iterable[Type[RouterAdapter]] = (),
        *,
        probe_attempts: int = 2,
        retry_delay: float = 0.2,
    ):
        self._adapter_types: List[Type[RouterAdapter]] = list(adapter_types)
        self._probe_attempts = max(1, probe_attempts)
        self._retry_delay = max(0.0, retry_delay)

    def register(self, adapter_type: Type[RouterAdapter]) -> None:
        if adapter_type not in self._adapter_types:
            self._adapter_types.append(adapter_type)

    @property
    def adapter_types(self) -> Tuple[Type[RouterAdapter], ...]:
        return tuple(self._adapter_types)

    def detect(self, base_url: str) -> Optional[RouterAdapter]:
        """Return the best approved adapter, preserving the original API."""
        return self.detect_with_report(base_url).adapter

    def detect_with_report(
        self,
        base_url: str,
        *,
        allow_experimental: bool = False,
    ) -> RegistryDetection:
        best = None
        best_result = None
        probes = []
        for adapter_type in self._adapter_types:
            maturity = adapter_type.maturity
            if maturity is AdapterMaturity.DISABLED or (
                maturity is AdapterMaturity.EXPERIMENTAL
                and not allow_experimental
            ):
                probes.append(
                    AdapterProbe(
                        adapter_id=adapter_type.adapter_id,
                        maturity=maturity,
                        skipped=True,
                    )
                )
                continue

            candidate = adapter_type(base_url)
            result = None
            last_error = None
            for attempt in range(self._probe_attempts):
                try:
                    result = candidate.detect()
                    break
                except AdapterError as error:
                    last_error = error
                    if attempt + 1 < self._probe_attempts:
                        time.sleep(self._retry_delay)
            if result is None:
                probes.append(
                    AdapterProbe(
                        adapter_id=adapter_type.adapter_id,
                        maturity=maturity,
                        error=str(last_error),
                    )
                )
                continue

            probes.append(
                AdapterProbe(
                    adapter_id=adapter_type.adapter_id,
                    maturity=maturity,
                    result=result,
                )
            )
            if result.adapter != adapter_type.adapter_id:
                raise ValueError(
                    f"{adapter_type.__name__}.detect() returned adapter "
                    f"{result.adapter!r}, expected {adapter_type.adapter_id!r}"
                )
            if not 0.0 <= result.confidence <= 1.0:
                raise ValueError("detection confidence must be between 0 and 1")
            if result.applies and (
                best_result is None
                or result.confidence > best_result.confidence
            ):
                best, best_result = candidate, result

        return RegistryDetection(best, best_result, tuple(probes))


def load_approved_adapter_types(
    approved_dir: Path = Path("/etc/tfg-ai/approved"),
) -> Tuple[Type[RouterAdapter], ...]:
    """Load only administrator-approved modules whose hash still matches."""
    approved_dir = Path(approved_dir)
    manifest_path = approved_dir / "manifest.json"
    if not manifest_path.is_file():
        return ()
    try:
        entries = json.loads(manifest_path.read_text(encoding="utf-8"))["adapters"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return ()

    loaded = []
    for entry in entries:
        try:
            filename = entry["file"]
            if Path(filename).name != filename:
                continue
            module_path = approved_dir / filename
            content = module_path.read_bytes()
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                continue
            module_name = f"tfg_approved_{entry['job_id']}"
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            candidates = []
            for value in vars(module).values():
                if (
                    isinstance(value, type)
                    and issubclass(value, RouterAdapter)
                    and value is not RouterAdapter
                    and value.__module__ == module_name
                    and value not in candidates
                ):
                    candidates.append(value)
            if len(candidates) != 1:
                continue
            adapter_type = candidates[0]
            if adapter_type.adapter_id != entry["adapter_id"]:
                continue
            adapter_type.maturity = AdapterMaturity.APPROVED
            loaded.append(adapter_type)
        except Exception:
            continue
    return tuple(loaded)


def create_default_registry(
    approved_dir: Path = Path("/etc/tfg-ai/approved"),
    integrations_dir: Path = Path("/etc/tfg-ai/integrations"),
) -> AdapterRegistry:
    """Build the local registry without performing router I/O."""
    from .adapters import (
        GLInetAdapter,
        MercusysMR1500XAdapter,
        XiaomiR4CMAdapter,
    )

    from .script_adapter import load_script_adapter_types

    built_in = (GLInetAdapter, MercusysMR1500XAdapter, XiaomiR4CMAdapter)
    return AdapterRegistry(
        (
            *built_in,
            *load_approved_adapter_types(approved_dir),
            *load_script_adapter_types(integrations_dir),
        )
    )
