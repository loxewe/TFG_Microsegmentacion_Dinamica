import hashlib
import json
import subprocess
from unittest.mock import patch

from router_adapters import Credentials, FeatureState
from router_adapters.script_adapter import (
    DEFAULT_INTEGRATIONS_DIR,
    load_script_adapter_types,
)


def test_default_integrations_directory_is_persistent():
    assert DEFAULT_INTEGRATIONS_DIR.as_posix() == "/etc/tfg-ai/integrations"


def test_hash_verified_script_behaves_like_an_approved_adapter(tmp_path):
    script = tmp_path / "generated.py"
    script.write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "integrations": [
                    {
                        "integration_id": "fixture-router-v1",
                        "file": script.name,
                        "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs.get("input", "")))
        action = command[2]
        if action == "detect":
            output = {
                "applies": True,
                "integration_id": "fixture-router-v1",
                "confidence": 0.95,
                "evidence": {"model": "fixture"},
            }
        elif action == "status":
            output = {"success": True, "wifi": "disabled", "dhcp": "unknown"}
        else:
            output = {"success": True, "changed": True}
        return subprocess.CompletedProcess(command, 0, json.dumps(output) + "\n", "")

    adapter_type = load_script_adapter_types(tmp_path)[0]
    adapter = adapter_type("http://router.test")
    with patch("router_adapters.script_adapter.subprocess.run", side_effect=execute):
        assert adapter.detect().applies is True
        adapter.authenticate(Credentials(username="admin", password="secret"))
        assert adapter.get_status().wifi is FeatureState.DISABLED
        assert adapter.disable_wifi().success is True

    assert all("secret" not in " ".join(command) for command, _ in calls)
    assert any('"password": "secret"' in stdin for _, stdin in calls)


def test_modified_script_is_not_loaded(tmp_path):
    script = tmp_path / "generated.py"
    script.write_text("# changed\n", encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "integrations": [
                    {
                        "integration_id": "fixture-router-v1",
                        "file": script.name,
                        "sha256": "0" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert load_script_adapter_types(tmp_path) == ()
