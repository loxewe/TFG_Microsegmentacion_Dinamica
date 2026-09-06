from router_adapters import (
    AdapterCapabilities,
    AdapterError,
    AdapterMaturity,
    AdapterRegistry,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterAdapter,
    RouterStatus,
    create_default_registry,
    load_approved_adapter_types,
)
from router_adapters.adapters import (
    GLInetAdapter,
    MercusysMR1500XAdapter,
    XiaomiR4CMAdapter,
)


class FakeAdapter(RouterAdapter):
    capabilities = AdapterCapabilities()
    confidence = 0.0
    applies = False

    def detect(self):
        return DetectionResult(
            applies=self.applies,
            adapter=self.adapter_id,
            confidence=self.confidence,
        )

    def authenticate(self, credentials: Credentials):
        return None

    def get_status(self):
        return RouterStatus(FeatureState.UNKNOWN, FeatureState.UNKNOWN)

    def disable_wifi(self):
        return OperationResult(True, True)

    def disable_dhcp(self):
        return OperationResult(True, True)


class LowConfidenceAdapter(FakeAdapter):
    adapter_id = "low"
    maturity = AdapterMaturity.APPROVED
    confidence = 0.4
    applies = True


class HighConfidenceAdapter(FakeAdapter):
    adapter_id = "high"
    maturity = AdapterMaturity.APPROVED
    confidence = 0.9
    applies = True


class ExperimentalAdapter(FakeAdapter):
    adapter_id = "experimental"
    maturity = AdapterMaturity.EXPERIMENTAL
    confidence = 1.0
    applies = True


class BrokenAdapter(FakeAdapter):
    adapter_id = "broken"
    maturity = AdapterMaturity.APPROVED

    def detect(self):
        raise AdapterError("probe failed")


class TransientAdapter(FakeAdapter):
    adapter_id = "transient"
    maturity = AdapterMaturity.APPROVED
    attempts = 0

    def detect(self):
        type(self).attempts += 1
        if type(self).attempts == 1:
            raise AdapterError("temporary failure")
        return DetectionResult(True, self.adapter_id, confidence=0.8)


def test_default_registry_declares_approved_and_experimental_adapters():
    registry = create_default_registry()

    assert registry.adapter_types[:3] == (
        GLInetAdapter,
        MercusysMR1500XAdapter,
        XiaomiR4CMAdapter,
    )
    assert GLInetAdapter.maturity is AdapterMaturity.APPROVED
    assert MercusysMR1500XAdapter.maturity is AdapterMaturity.EXPERIMENTAL
    assert XiaomiR4CMAdapter.maturity is AdapterMaturity.APPROVED


def test_registry_reports_all_probes_and_returns_highest_confidence():
    registry = AdapterRegistry(
        (LowConfidenceAdapter, BrokenAdapter, HighConfidenceAdapter)
    )

    report = registry.detect_with_report("http://router.test")

    assert report.supported is True
    assert isinstance(report.adapter, HighConfidenceAdapter)
    assert report.detection.adapter == "high"
    assert report.probes[1].error == "probe failed"
    assert registry.detect("http://router.test").adapter_id == "high"


def test_experimental_adapter_requires_explicit_opt_in():
    registry = AdapterRegistry((ExperimentalAdapter,))

    safe_report = registry.detect_with_report("http://router.test")
    experimental_report = registry.detect_with_report(
        "http://router.test",
        allow_experimental=True,
    )

    assert safe_report.supported is False
    assert safe_report.probes[0].skipped is True
    assert isinstance(experimental_report.adapter, ExperimentalAdapter)


def test_registry_retries_transient_probe_error_once():
    TransientAdapter.attempts = 0
    registry = AdapterRegistry((TransientAdapter,), retry_delay=0)

    report = registry.detect_with_report("http://router.test")

    assert report.supported is True
    assert report.adapter.adapter_id == "transient"
    assert TransientAdapter.attempts == 2


def test_modified_approved_adapter_is_not_loaded(tmp_path):
    adapter_file = tmp_path / "generated.py"
    adapter_file.write_text("original", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        '{"adapters":[{"adapter_id":"generated","file":"generated.py",'
        '"sha256":"not-the-real-hash","job_id":"fixture"}]}',
        encoding="utf-8",
    )

    assert load_approved_adapter_types(tmp_path) == ()
