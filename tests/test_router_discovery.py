import hashlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from router_adapters import (
    AdapterRegistry,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterStatus,
    VerificationResult,
    load_approved_adapter_types,
)
from router_discovery import (
    apply_candidate_job,
    approve_job,
    build_prompt,
    collect_public_evidence,
    create_job,
    hardware_test_job,
    _load_candidate_type,
    prepare_workspace,
    read_job,
    run_job,
    validate_candidate,
    validate_script_candidate,
)


CANDIDATE = '''
from router_adapters import (
    AdapterMaturity, Credentials, DetectionResult, FeatureState,
    OperationResult, RouterAdapter, RouterStatus,
)


class GeneratedFixtureAdapter(RouterAdapter):
    adapter_id = "generated-fixture"
    maturity = AdapterMaturity.EXPERIMENTAL

    def detect(self):
        return DetectionResult(True, self.adapter_id, confidence=0.9)

    def authenticate(self, credentials: Credentials):
        return None

    def get_status(self):
        return RouterStatus(FeatureState.UNKNOWN, FeatureState.UNKNOWN)

    def disable_wifi(self):
        return OperationResult(False, False, "unsupported")

    def disable_dhcp(self):
        return OperationResult(False, False, "unsupported")
'''

REPORT = {
    "evidence": [],
    "capabilities": {"wifi_status": True, "disable_wifi": True},
    "limitations": [],
    "write_tests_required": ["disable_wifi"],
}


def write_candidate_bundle(candidate_dir):
    candidate_dir.mkdir(parents=True, exist_ok=True)
    (candidate_dir / "adapter.py").write_text(CANDIDATE, encoding="utf-8")
    (candidate_dir / "test_adapter.py").write_text(
        "def test_candidate_shape():\n    assert True\n",
        encoding="utf-8",
    )
    (candidate_dir / "report.json").write_text(
        json.dumps(REPORT),
        encoding="utf-8",
    )


def write_script_bundle(candidate_dir, success=True):
    candidate_dir.mkdir(parents=True, exist_ok=True)
    (candidate_dir / "switcher.py").write_text(
        "import json\nusername = None\nprint(json.dumps({'ok': True}))\n",
        encoding="utf-8",
    )
    (candidate_dir / "report.json").write_text(
        json.dumps({"evidence": ["fixture"]}), encoding="utf-8"
    )
    (candidate_dir / "result.json").write_text(
        json.dumps(
            {
                "success": success,
                "integration_id": "generated-script-fixture",
                "before": "enabled",
                "after": "disabled" if success else "unknown",
            }
        ),
        encoding="utf-8",
    )


SCRIPT_VALIDATION = {
    "valid": True,
    "integration_id": "generated-script-fixture",
    "errors": [],
    "observation": {"wifi": "disabled", "dhcp": "unknown", "confidence": 0.9},
    "report": {"evidence": ["fixture"]},
}


def test_direct_candidate_requires_real_detect_and_disabled_status(tmp_path):
    candidate = tmp_path / "candidate"
    write_script_bundle(candidate)
    responses = [
        {
            "applies": True,
            "integration_id": "generated-script-fixture",
            "confidence": 0.93,
        },
        {"success": True, "wifi": "disabled", "dhcp": "unknown"},
    ]

    with patch("router_discovery.run_script_command", side_effect=responses):
        validation = validate_script_candidate(
            candidate,
            target_base_url="http://router.test",
            username="admin",
            password="fixture-secret",
        )

    assert validation["valid"] is True
    assert validation["integration_id"] == "generated-script-fixture"
    assert validation["observation"]["wifi"] == "disabled"


def test_job_metadata_never_contains_credentials(tmp_path):
    credentials_dir = tmp_path / "runtime-credentials"
    status = create_job(
        "http://192.0.2.1/",
        mode="assisted",
        state_dir=tmp_path,
        credentials_dir=credentials_dir,
        username="admin",
        password="fixture-secret",
    )
    job_dir = tmp_path / "jobs" / status["job_id"]
    request_text = (job_dir / "request.json").read_text(encoding="utf-8")

    assert "password" not in request_text.lower()
    credentials_path = credentials_dir / f"{status['job_id']}.json"
    assert json.loads(credentials_path.read_text(encoding="utf-8")) == {
        "username": "admin",
        "password": "fixture-secret",
    }
    if os.name == "posix":
        assert credentials_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(request_text)["base_url"] == "http://192.0.2.1"
    assert status["status"] == "pending"


def test_public_evidence_uses_get_and_ignores_external_assets(tmp_path):
    root_response = Mock()
    root_response.status_code = 200
    root_response.headers = {"Content-Type": "text/html"}
    root_response.encoding = "utf-8"
    root_response.iter_content.return_value = [
        b'<script src="/router.js"></script><script src="https://evil.test/x.js"></script>'
    ]
    script_response = Mock()
    script_response.status_code = 200
    script_response.headers = {"Content-Type": "application/javascript"}
    script_response.encoding = "utf-8"
    script_response.iter_content.return_value = [b"const router = true;"]
    session = Mock()
    session.headers = {}
    session.get.side_effect = [root_response, script_response]

    with patch("router_discovery.requests.Session", return_value=session):
        records = list(
            collect_public_evidence("http://router.test", tmp_path / "evidence")
        )

    assert [item["url"] for item in records] == [
        "http://router.test",
        "http://router.test/router.js",
    ]
    assert all(call.args[0].startswith("http://router.test") for call in session.get.call_args_list)
    assert all(call.kwargs["allow_redirects"] is False for call in session.get.call_args_list)


def test_clean_room_workspace_has_no_approved_adapter_examples(tmp_path):
    job = create_job("http://router.test", mode="clean_room", state_dir=tmp_path)
    job_dir = tmp_path / "jobs" / job["job_id"]

    workspace = prepare_workspace(job_dir, Path(__file__).parents[1], "clean_room")

    assert (workspace / "reference" / "router_adapters" / "base.py").is_file()
    assert (workspace / "reference" / "router_adapters" / "registry.py").is_file()
    assert not (workspace / "reference" / "approved_adapters").exists()


def test_assisted_workspace_copies_only_approved_examples(tmp_path):
    job = create_job("http://router.test", mode="assisted", state_dir=tmp_path)
    job_dir = tmp_path / "jobs" / job["job_id"]

    workspace = prepare_workspace(job_dir, Path(__file__).parents[1], "assisted")
    names = {path.name for path in (workspace / "reference" / "approved_adapters").iterdir()}

    assert names == {"glinet.py", "xiaomi_r4cm.py"}
    assert "mercusys_mr1500x.py" not in names
    assert (
        workspace
        / "reference"
        / "legacy_integrations"
        / "ZTE_Legacy_Digi"
        / "conmutar_zte_legacy.py"
    ).is_file()
    assert (
        workspace
        / "reference"
        / "legacy_integrations"
        / "ZTE_H298A_MasMovil"
        / "conmutar_zte_requests.py"
    ).is_file()


def test_prompt_defines_direct_script_contract_and_real_verification():
    prompt = build_prompt(
        {"base_url": "http://router.test", "mode": "assisted"}
    )

    assert "candidate/switcher.py" in prompt
    assert "ACTION es detect, status u off" in prompt
    assert "No cambies DHCP" in prompt
    assert "Ejecutar ese script contra el router" in prompt
    assert '"before": "enabled"' in prompt
    assert '"after": "disabled"' in prompt
    assert "reference/legacy_integrations" in prompt
    assert "acceso completo" in prompt
    assert "No te detengas para pedir confirmación" in prompt


def test_candidate_loader_ignores_alias_of_same_adapter_class(tmp_path):
    candidate = tmp_path / "adapter.py"
    candidate.write_text(
        CANDIDATE + "\nAdapter = GeneratedFixtureAdapter\n",
        encoding="utf-8",
    )

    adapter_type = _load_candidate_type(candidate, "a" * 32)

    assert adapter_type.adapter_id == "generated-fixture"


def test_run_job_uses_workspace_write_and_returns_to_web_ready(tmp_path):
    credentials_dir = tmp_path / "runtime-credentials"
    integrations_dir = tmp_path / "persistent-integrations"
    job = create_job(
        "http://router.test",
        mode="assisted",
        state_dir=tmp_path,
        credentials_dir=credentials_dir,
        password="fixture-secret",
    )

    def fake_codex(command, **kwargs):
        write_script_bundle(Path(kwargs["cwd"]) / "candidate")
        return subprocess.CompletedProcess(command, 0)

    with (
        patch("router_discovery.collect_public_evidence", return_value=[]),
        patch("router_discovery.subprocess.run", side_effect=fake_codex) as run,
        patch("router_discovery.validate_script_candidate", return_value=SCRIPT_VALIDATION),
    ):
        status = run_job(
            job["job_id"],
            state_dir=tmp_path,
            project_dir=Path(__file__).parents[1],
            codex_binary="/fixture/codex",
            credentials_dir=credentials_dir,
            integrations_dir=integrations_dir,
        )

    command = run.call_args.args[0]
    assert command[:4] == [
        "/fixture/codex",
        "--ask-for-approval",
        "never",
        "exec",
    ]
    assert command[command.index("--sandbox") + 1] == "workspace-write"
    assert "sandbox_workspace_write.network_access=true" in command
    assert "danger-full-access" not in command
    assert status["status"] == "script_ready"
    assert status["validation"]["integration_id"] == "generated-script-fixture"
    assert Path(status["approved_file"]).parent == integrations_dir
    assert (integrations_dir / "manifest.json").is_file()
    assert not (tmp_path / "integrations").exists()
    assert not (credentials_dir / f"{job['job_id']}.json").exists()


def test_successful_portal_job_completes_local_migration_automatically(tmp_path):
    credentials_dir = tmp_path / "runtime-credentials"
    job = create_job(
        "http://router.test",
        mode="assisted",
        state_dir=tmp_path,
        credentials_dir=credentials_dir,
        username="admin",
        password="router-secret",
        ssid="Original Home",
        wifi_password="wifi-secret",
    )

    def fake_codex(command, **kwargs):
        write_script_bundle(Path(kwargs["cwd"]) / "candidate")
        return subprocess.CompletedProcess(command, 0)

    with (
        patch("router_discovery.collect_public_evidence", return_value=[]),
        patch("router_discovery.subprocess.run", side_effect=fake_codex),
        patch("router_discovery.validate_script_candidate", return_value=SCRIPT_VALIDATION),
        patch("router_discovery.complete_setup_after_discovery", return_value=True) as complete,
    ):
        status = run_job(
            job["job_id"],
            state_dir=tmp_path,
            project_dir=Path(__file__).parents[1],
            codex_binary="/fixture/codex",
            credentials_dir=credentials_dir,
        )

    assert status["status"] == "completed"
    complete.assert_called_once_with("Original Home", "wifi-secret")
    assert not (credentials_dir / f"{job['job_id']}.json").exists()


def test_unverified_direct_script_is_not_registered(tmp_path):
    job = create_job("http://router.test", state_dir=tmp_path)

    def fake_codex(command, **kwargs):
        candidate_dir = Path(kwargs["cwd"]) / "candidate"
        write_script_bundle(candidate_dir, success=False)
        return subprocess.CompletedProcess(command, 0)

    with (
        patch("router_discovery.collect_public_evidence", return_value=[]),
        patch("router_discovery.subprocess.run", side_effect=fake_codex),
        patch(
            "router_discovery.validate_script_candidate",
            return_value={**SCRIPT_VALIDATION, "valid": False, "errors": ["not verified"]},
        ),
    ):
        status = run_job(
            job["job_id"],
            state_dir=tmp_path,
            project_dir=Path(__file__).parents[1],
            codex_binary="/fixture/codex",
        )

    assert status["status"] == "failed_validation"
    assert not (tmp_path / "integrations" / "manifest.json").exists()


def test_short_secret_does_not_corrupt_executable_candidate_files(tmp_path):
    credentials_dir = tmp_path / "runtime-credentials"
    job = create_job(
        "http://router.test",
        state_dir=tmp_path,
        credentials_dir=credentials_dir,
        password="user",
    )

    def fake_codex(command, **kwargs):
        candidate_dir = Path(kwargs["cwd"]) / "candidate"
        write_script_bundle(candidate_dir)
        result_path = candidate_dir / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["integration_id"] = "zte-user-ui"
        result_path.write_text(json.dumps(result), encoding="utf-8")
        (candidate_dir / "report.json").write_text(
            json.dumps({"variant": "user interface"}), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0)

    with (
        patch("router_discovery.collect_public_evidence", return_value=[]),
        patch("router_discovery.subprocess.run", side_effect=fake_codex),
        patch(
            "router_discovery.validate_script_candidate",
            return_value={
                **SCRIPT_VALIDATION,
                "integration_id": "zte-user-ui",
            },
        ),
    ):
        status = run_job(
            job["job_id"],
            state_dir=tmp_path,
            project_dir=Path(__file__).parents[1],
            codex_binary="/fixture/codex",
            credentials_dir=credentials_dir,
        )

    source = (
        tmp_path / "jobs" / job["job_id"] / "workspace" / "candidate" / "switcher.py"
    ).read_text(encoding="utf-8")
    assert status["status"] == "script_ready"
    assert "username" in source
    assert "[REDACTED]name" not in source
    result_text = (
        tmp_path / "jobs" / job["job_id"] / "workspace" / "candidate" / "result.json"
    ).read_text(encoding="utf-8")
    report_text = (
        tmp_path / "jobs" / job["job_id"] / "workspace" / "candidate" / "report.json"
    ).read_text(encoding="utf-8")
    assert "zte-user-ui" in result_text
    assert "user interface" in report_text


def test_static_validation_rejects_subprocess_and_missing_contract(tmp_path):
    candidate = tmp_path / "adapter.py"
    candidate.write_text(
        "import subprocess\nclass Bad(RouterAdapter):\n    adapter_id='bad'\n",
        encoding="utf-8",
    )

    result = validate_candidate(candidate)

    assert result["valid"] is False
    assert any("subprocess" in error for error in result["errors"])
    assert any("missing methods" in error for error in result["errors"])


def test_hardware_verified_candidate_is_hashed_and_loadable(tmp_path):
    job = create_job("http://router.test", state_dir=tmp_path)
    job_dir = tmp_path / "jobs" / job["job_id"]
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    write_candidate_bundle(candidate.parent)
    candidate.write_text(
        candidate.read_text(encoding="utf-8")
        + "\nAdapter = GeneratedFixtureAdapter\n",
        encoding="utf-8",
    )
    status_path = job_dir / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["status"] = "awaiting_approval"
    status_path.write_text(json.dumps(status), encoding="utf-8")

    reviewed = approve_job(job["job_id"], state_dir=tmp_path)
    assert load_approved_adapter_types(tmp_path / "approved") == ()
    adapter = Mock()
    adapter.detect.return_value = DetectionResult(
        True,
        "generated-fixture",
        confidence=0.9,
    )
    adapter.get_status.return_value = RouterStatus(
        FeatureState.ENABLED,
        FeatureState.UNKNOWN,
    )
    adapter.disable_wifi.return_value = OperationResult(True, True)
    adapter.verify.return_value = VerificationResult(
        True,
        RouterStatus(FeatureState.DISABLED, FeatureState.UNKNOWN),
        expected_wifi=FeatureState.DISABLED,
    )
    adapter_type = Mock(return_value=adapter)
    with patch("router_discovery._load_candidate_type", return_value=adapter_type):
        approved = hardware_test_job(
            job["job_id"],
            state_dir=tmp_path,
            password="fixture-secret",
            confirm_disable_wifi=True,
        )
    loaded = load_approved_adapter_types(tmp_path / "approved")

    assert reviewed["status"] == "approved_for_hardware_test"
    assert approved["status"] == "approved"
    assert approved["sha256"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert len(loaded) == 1
    assert loaded[0].adapter_id == "generated-fixture"
    assert loaded[0].maturity.value == "approved"
    assert (
        AdapterRegistry(loaded).detect("http://router.test").adapter_id
        == "generated-fixture"
    )
    assert read_job(job["job_id"], tmp_path)["status"] == "approved"
    adapter.authenticate.assert_called_once()
    adapter.verify.assert_called_once_with(wifi=FeatureState.DISABLED)


def test_hardware_test_requires_explicit_confirmation(tmp_path):
    job = create_job("http://router.test", state_dir=tmp_path)

    with pytest.raises(ValueError, match="confirm-disable-wifi"):
        hardware_test_job(job["job_id"], state_dir=tmp_path)


def test_ready_candidate_is_verified_then_registered(tmp_path):
    job = create_job("http://router.test", state_dir=tmp_path)
    job_dir = tmp_path / "jobs" / job["job_id"]
    write_candidate_bundle(job_dir / "workspace" / "candidate")
    status = json.loads((job_dir / "status.json").read_text(encoding="utf-8"))
    status["status"] = "ready_for_migration"
    (job_dir / "status.json").write_text(json.dumps(status), encoding="utf-8")

    adapter = Mock()
    adapter.detect.return_value = DetectionResult(
        True, "generated-fixture", confidence=0.9
    )
    adapter.get_status.return_value = RouterStatus(
        FeatureState.ENABLED, FeatureState.ENABLED
    )
    adapter.disable_wifi.return_value = OperationResult(True, True)
    adapter.verify.side_effect = [
        VerificationResult(
            False,
            RouterStatus(FeatureState.ENABLED, FeatureState.ENABLED),
            expected_wifi=FeatureState.DISABLED,
        ),
        VerificationResult(
            True,
            RouterStatus(FeatureState.DISABLED, FeatureState.ENABLED),
            expected_wifi=FeatureState.DISABLED,
        ),
    ]
    with patch(
        "router_discovery._load_candidate_type",
        return_value=Mock(return_value=adapter),
    ):
        result = apply_candidate_job(
            job["job_id"],
            state_dir=tmp_path,
            username="admin",
            password="fixture-secret",
            verify_attempts=2,
            verify_delay=0,
        )

    assert result["status"] == "approved"
    assert (tmp_path / "approved" / "manifest.json").is_file()
    adapter.disable_wifi.assert_called_once_with()
    assert adapter.verify.call_count == 2
