"""Isolated Codex discovery jobs for unsupported domestic routers."""

import argparse
import ast
import getpass
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional
from urllib.parse import urljoin, urlsplit

import requests

from router_adapters import AdapterMaturity, Credentials, run_script_command
from router_adapters.adapters import (
    GLInetAdapter,
    MercusysMR1500XAdapter,
    XiaomiR4CMAdapter,
)
from router_integration import normalize_router_url


DEFAULT_STATE_DIR = Path("/var/lib/tfg-ai")
DEFAULT_APPROVED_DIR = Path("/etc/tfg-ai/approved")
DEFAULT_INTEGRATIONS_DIR = Path("/etc/tfg-ai/integrations")
DEFAULT_PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_CREDENTIALS_DIR = Path("/tmp/tfg-ai-credentials")
JOB_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
DISCOVERY_MODES = {"assisted", "clean_room"}
MAX_RESOURCE_BYTES = 1024 * 1024
MAX_RESOURCES = 12
RESERVED_ADAPTER_IDS = {"glinet", "mercusys-mr1500x", "xiaomi-r4cm"}
REQUIRED_METHODS = {
    "detect",
    "authenticate",
    "get_status",
    "disable_wifi",
    "disable_dhcp",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, value: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


def _job_dir(state_dir: Path, job_id: str) -> Path:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError("invalid discovery job id")
    return state_dir / "jobs" / job_id


def read_job(job_id: str, state_dir: Path = DEFAULT_STATE_DIR) -> Dict:
    path = _job_dir(Path(state_dir), job_id) / "status.json"
    if not path.is_file():
        raise FileNotFoundError(f"discovery job {job_id} does not exist")
    return json.loads(path.read_text(encoding="utf-8"))


def update_job(job_dir: Path, status: str, message: str, **extra) -> Dict:
    path = job_dir / "status.json"
    current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    current.update(
        status=status,
        message=message,
        updated_at=utc_now(),
        **extra,
    )
    _atomic_json(path, current)
    return current


def create_job(
    base_url: str,
    *,
    mode: str = "clean_room",
    state_dir: Path = DEFAULT_STATE_DIR,
    credentials_dir: Path = DEFAULT_CREDENTIALS_DIR,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ssid: Optional[str] = None,
    wifi_password: Optional[str] = None,
) -> Dict:
    normalized_url = normalize_router_url(base_url)
    if mode not in DISCOVERY_MODES:
        raise ValueError("discovery mode must be assisted or clean_room")
    job_id = uuid.uuid4().hex
    job_dir = _job_dir(Path(state_dir), job_id)
    (job_dir / "workspace" / "candidate").mkdir(parents=True)
    request_data = {
        "job_id": job_id,
        "base_url": normalized_url,
        "mode": mode,
        "created_at": utc_now(),
    }
    _atomic_json(job_dir / "request.json", request_data)
    if password:
        credentials_dir = Path(credentials_dir)
        credentials_dir.mkdir(parents=True, exist_ok=True)
        credentials_dir.chmod(0o700)
        credentials_path = credentials_dir / f"{job_id}.json"
        temporary = credentials_path.with_suffix(".json.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                secrets = {"username": username or "", "password": password}
                if ssid is not None:
                    secrets["ssid"] = ssid
                if wifi_password is not None:
                    secrets["wifi_password"] = wifi_password
                json.dump(secrets, stream)
                stream.write("\n")
            temporary.replace(credentials_path)
            credentials_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
    return update_job(
        job_dir,
        "pending",
        "Trabajo creado; todavía no se ha contactado con Codex.",
        job_id=job_id,
        mode=mode,
        created_at=request_data["created_at"],
    )


def _same_origin(candidate: str, base_url: str) -> bool:
    candidate_parts = urlsplit(candidate)
    base_parts = urlsplit(base_url)
    return (
        candidate_parts.scheme,
        candidate_parts.hostname,
        candidate_parts.port,
    ) == (base_parts.scheme, base_parts.hostname, base_parts.port)


def _read_limited(response, limit: int = MAX_RESOURCE_BYTES) -> bytes:
    content = bytearray()
    for chunk in response.iter_content(16384):
        content.extend(chunk)
        if len(content) > limit:
            raise ValueError("router resource exceeds the evidence size limit")
    return bytes(content)


def collect_public_evidence(base_url: str, evidence_dir: Path) -> Iterable[Dict]:
    """Collect same-origin public pages using GET only and without credentials."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers["User-Agent"] = "tfg-router-discovery/1.0"
    queue = [base_url]
    seen = set()
    records = []
    while queue and len(seen) < MAX_RESOURCES:
        url = queue.pop(0)
        if url in seen or not _same_origin(url, base_url):
            continue
        seen.add(url)
        record = {"url": url}
        try:
            response = session.get(
                url,
                timeout=8,
                allow_redirects=False,
                stream=True,
            )
            body = _read_limited(response)
            record.update(status=response.status_code, bytes=len(body))
            suffix = Path(urlsplit(url).path).suffix.lower()
            extension = suffix if suffix in {".html", ".htm", ".js", ".json"} else ".txt"
            filename = f"{len(records):02d}-{hashlib.sha256(url.encode()).hexdigest()[:12]}{extension}"
            (evidence_dir / filename).write_bytes(body)
            record["file"] = filename

            content_type = response.headers.get("Content-Type", "").lower()
            if len(records) == 0 and ("html" in content_type or extension in {".html", ".htm", ".txt"}):
                text = body.decode(response.encoding or "utf-8", errors="replace")
                for reference in re.findall(
                    r"(?:src|href)=[\"']([^\"']+)[\"']",
                    text,
                    flags=re.IGNORECASE,
                ):
                    child = urljoin(base_url + "/", reference)
                    if _same_origin(child, base_url) and urlsplit(child).path.lower().endswith(".js"):
                        queue.append(child)
        except (requests.RequestException, ValueError) as error:
            record["error"] = str(error)
        records.append(record)

    _atomic_json(evidence_dir / "index.json", {"resources": records})
    return records


def _copy_reference(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def prepare_workspace(job_dir: Path, project_dir: Path, mode: str) -> Path:
    workspace = job_dir / "workspace"
    reference = workspace / "reference"
    for name in (
        "__init__.py",
        "base.py",
        "models.py",
        "errors.py",
        "registry.py",
        "README.md",
    ):
        _copy_reference(
            project_dir / "router_adapters" / name,
            reference / "router_adapters" / name,
        )
    _copy_reference(
        project_dir / "tests" / "test_router_registry.py",
        reference / "tests" / "test_router_registry.py",
    )
    if mode == "assisted":
        for adapter_type in (
            GLInetAdapter,
            MercusysMR1500XAdapter,
            XiaomiR4CMAdapter,
        ):
            if adapter_type.maturity is not AdapterMaturity.APPROVED:
                continue
            source = project_dir / "router_adapters" / "adapters" / (
                Path(sys.modules[adapter_type.__module__].__file__).name
            )
            _copy_reference(source, reference / "approved_adapters" / source.name)
        legacy_root = project_dir / "Scripts_Finales"
        for source in legacy_root.rglob("*"):
            if source.is_file() and source.suffix.lower() in {".py", ".md", ".txt"}:
                relative = source.relative_to(legacy_root)
                _copy_reference(
                    source,
                    reference / "legacy_integrations" / relative,
                )
    return workspace


def build_prompt(
    request_data: Dict,
    credentials_path: Optional[Path] = None,
) -> str:
    mode = request_data["mode"]
    references = (
        "Usa libremente reference/approved_adapters, "
        "reference/legacy_integrations y el código del proyecto como referencias. "
        "Prioriza conseguir una integración funcional en el router real."
        if mode == "assisted"
        else "Trabaja en evaluación clean-room usando el router y el contrato de salida."
    )
    credentials = (
        f"Las credenciales temporales están en {credentials_path}. "
        "El JSON contiene username/password del router y puede contener "
        "ssid/wifi_password reservados para configurar después la Raspberry. "
        "Usa solo username/password contra el router. No muestres, copies ni "
        "incluyas ninguno de esos valores en código, logs o resultados."
        if credentials_path and credentials_path.is_file()
        else "No hay credenciales disponibles; limita el trabajo a recursos públicos."
    )
    return f"""Integra directamente el router situado en {request_data['base_url']}.

{references} Puedes analizar HTML y JavaScript, crear y ejecutar scripts,
autenticarte, probar hipótesis y consultar Internet si resulta útil. Tienes
acceso completo porque el objetivo es obtener una integración funcional. La
URL objetivo debe recibirse por argumento y no quedar fija en el resultado.
{credentials}

Tu tarea termina únicamente cuando hayas hecho todo esto:
1. Identificar el router y reconstruir su autenticación.
2. Leer el estado Wi-Fi real.
3. Crear candidate/switcher.py.
4. Ejecutar ese script contra el router para desactivar exclusivamente sus
   radios Wi-Fi. No cambies DHCP, credenciales, WAN ni la red de la Raspberry.
5. Esperar la convergencia y volver a leer el estado hasta confirmar que todas
   las radios están desactivadas.
6. Escribir candidate/result.json con el resultado real y candidate/report.json
   con las evidencias. Si no puedes verificar el apagado, success debe ser false.

Contrato obligatorio de switcher.py:
- CLI: `python3 switcher.py ACTION --base-url URL`.
- ACTION es detect, status u off.
- detect es público y read-only. Devuelve en la última línea un JSON con
  applies, integration_id, confidence y evidence.
- status y off leen de stdin un JSON {{"username": ..., "password": ...}}.
- status devuelve {{"success": true, "wifi": "enabled|disabled|unknown",
  "dhcp": "unknown", "details": {{...}}}}.
- off devuelve {{"success": true, "changed": true, "message": "..."}}.
- Los mensajes de diagnóstico pueden preceder al JSON, pero la última línea
  siempre debe ser el resultado JSON.
- No incluyas contraseñas, cookies ni tokens persistentes en ningún archivo.
- integration_id debe ser estable, minúsculo y específico de modelo/firmware.

candidate/result.json debe contener exactamente como mínimo:
{{
  "success": true,
  "integration_id": "fabricante-modelo-variante",
  "before": "enabled",
  "after": "disabled"
}}

Puedes modificar libremente tus archivos de trabajo y ejecutar las pruebas que
necesites. No te detengas para pedir confirmación: el usuario ha iniciado
expresamente esta migración desde el portal. Finaliza dejando switcher.py,
result.json y report.json en candidate/.
"""


def validate_candidate(
    candidate_path: Path,
    *,
    target_base_url: Optional[str] = None,
) -> Dict:
    errors = []
    adapter_id = None
    experimental_maturity = False
    if not candidate_path.is_file():
        return {"valid": False, "adapter_id": None, "errors": ["candidate/adapter.py is missing"]}
    if candidate_path.stat().st_size > 256 * 1024:
        return {"valid": False, "adapter_id": None, "errors": ["candidate adapter is too large"]}
    try:
        source = candidate_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError) as error:
        return {"valid": False, "adapter_id": None, "errors": [str(error)]}

    adapter_classes = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imported = [alias.name for alias in node.names]
            if "subprocess" in imported:
                errors.append("candidate adapters may not import subprocess")
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            base.id if isinstance(base, ast.Name) else base.attr
            for base in node.bases
            if isinstance(base, (ast.Name, ast.Attribute))
        }
        if "RouterAdapter" not in base_names:
            continue
        adapter_classes.append(node)
        methods = {
            child.name for child in node.body if isinstance(child, ast.FunctionDef)
        }
        missing = sorted(REQUIRED_METHODS - methods)
        if missing:
            errors.append("missing methods: " + ", ".join(missing))
        for child in node.body:
            if not isinstance(child, ast.Assign):
                continue
            if any(isinstance(target, ast.Name) and target.id == "adapter_id" for target in child.targets):
                if isinstance(child.value, ast.Constant) and isinstance(child.value.value, str):
                    adapter_id = child.value.value
            if any(isinstance(target, ast.Name) and target.id == "maturity" for target in child.targets):
                experimental_maturity = (
                    isinstance(child.value, ast.Attribute)
                    and child.value.attr == "EXPERIMENTAL"
                )

    if len(adapter_classes) != 1:
        errors.append("candidate must define exactly one RouterAdapter subclass")
    if not adapter_id or adapter_id == "unknown":
        errors.append("candidate must declare a unique adapter_id")
    if adapter_id in RESERVED_ADAPTER_IDS:
        errors.append("candidate adapter_id collides with a built-in adapter")
    if not experimental_maturity:
        errors.append("candidate must declare AdapterMaturity.EXPERIMENTAL")
    if target_base_url:
        target_host = urlsplit(target_base_url).hostname
        if target_base_url in source or (target_host and target_host in source):
            errors.append("candidate must not hard-code the discovery router URL")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            errors.append(f"candidate adapters may not call {node.func.id}")

    tests_path = candidate_path.parent / "test_adapter.py"
    if not tests_path.is_file():
        errors.append("candidate/test_adapter.py is missing")
    else:
        try:
            ast.parse(tests_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append(f"candidate tests are invalid: {error}")
    report_path = candidate_path.parent / "report.json"
    if not report_path.is_file():
        errors.append("candidate/report.json is missing")
    else:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            required_report = {
                "evidence",
                "capabilities",
                "limitations",
                "write_tests_required",
            }
            if not isinstance(report, dict):
                errors.append("candidate report must be a JSON object")
            else:
                missing_report = sorted(required_report - set(report))
                if missing_report:
                    errors.append(
                        "candidate report missing: " + ", ".join(missing_report)
                    )
                expected_types = {
                    "evidence": list,
                    "capabilities": dict,
                    "limitations": list,
                    "write_tests_required": list,
                }
                for key, expected_type in expected_types.items():
                    if key in report and not isinstance(report[key], expected_type):
                        errors.append(
                            f"candidate report field {key} has invalid type"
                        )
        except (OSError, UnicodeError, ValueError, TypeError) as error:
            errors.append(f"candidate report is invalid: {error}")

    hardware_test_ready = False
    if "report" in locals() and isinstance(report, dict):
        capabilities = report.get("capabilities", {})
        hardware_test_ready = bool(
            isinstance(capabilities, dict)
            and capabilities.get("wifi_status") is True
            and capabilities.get("disable_wifi") is True
            and "disable_wifi" in report.get("write_tests_required", [])
        )
    return {
        "valid": not errors,
        "adapter_id": adapter_id,
        "errors": errors,
        "hardware_test_ready": hardware_test_ready,
    }


def validate_script_candidate(
    candidate_dir: Path,
    *,
    target_base_url: str,
    username: Optional[str],
    password: str,
) -> Dict:
    """Validate the small script protocol against the router after Codex ran it."""
    candidate_dir = Path(candidate_dir)
    script = candidate_dir / "switcher.py"
    report_path = candidate_dir / "report.json"
    result_path = candidate_dir / "result.json"
    errors = []
    integration_id = None
    if not script.is_file():
        errors.append("candidate/switcher.py is missing")
    else:
        try:
            source = script.read_text(encoding="utf-8")
            if script.stat().st_size > 256 * 1024:
                errors.append("candidate switcher is too large")
            ast.parse(source)
            target_host = urlsplit(target_base_url).hostname
            if target_base_url in source or (target_host and target_host in source):
                errors.append("switcher must not hard-code the discovery router URL")
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append(f"candidate switcher is invalid: {error}")

    report = None
    result = None
    for path, label in ((report_path, "report"), (result_path, "result")):
        if not path.is_file():
            errors.append(f"candidate/{path.name} is missing")
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("must be a JSON object")
            if label == "report":
                report = document
            else:
                result = document
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"candidate {label} is invalid: {error}")

    if isinstance(result, dict):
        integration_id = result.get("integration_id")
        if not isinstance(integration_id, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{2,63}", integration_id or ""
        ):
            errors.append("result has an invalid integration_id")
        if integration_id in RESERVED_ADAPTER_IDS:
            errors.append("generated integration_id collides with a built-in adapter")
        if result.get("success") is not True or result.get("after") != "disabled":
            errors.append("Codex did not verify the real Wi-Fi shutdown")

    observation = None
    if not errors:
        try:
            detection = run_script_command(script, "detect", target_base_url)
            if (
                detection.get("applies") is not True
                or detection.get("integration_id") != integration_id
            ):
                raise ValueError("saved script did not detect the target router")
            confidence = float(detection.get("confidence", 0.0))
            if not 0.0 <= confidence <= 1.0:
                raise ValueError("detection confidence must be between 0 and 1")
            status = run_script_command(
                script,
                "status",
                target_base_url,
                Credentials(username=username, password=password),
            )
            if status.get("success") is not True or status.get("wifi") != "disabled":
                raise ValueError("saved script did not confirm Wi-Fi as disabled")
            observation = {
                "wifi": status.get("wifi"),
                "dhcp": status.get("dhcp", "unknown"),
                "confidence": confidence,
            }
        except Exception as error:
            errors.append(str(error))
    return {
        "valid": not errors,
        "integration_id": integration_id,
        "errors": errors,
        "observation": observation,
        "report": report,
    }


def promote_script_candidate(
    job_dir: Path,
    state_dir: Path,
    validation: Dict,
    integrations_dir: Optional[Path] = None,
) -> Dict:
    """Store a verified script and a hash-protected registry entry."""
    integrations_dir = (
        Path(integrations_dir)
        if integrations_dir is not None
        else Path(state_dir) / "integrations"
    )
    integrations_dir.mkdir(parents=True, exist_ok=True)
    integrations_dir.chmod(0o700)
    source = job_dir / "workspace" / "candidate" / "switcher.py"
    content = source.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    filename = f"{job_dir.name}-{validation['integration_id']}.py"
    destination = integrations_dir / filename
    destination.write_bytes(content)
    destination.chmod(0o600)

    manifest_path = integrations_dir / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.is_file()
        else {"integrations": []}
    )
    if any(
        item.get("integration_id") == validation["integration_id"]
        for item in manifest.get("integrations", [])
    ):
        destination.unlink(missing_ok=True)
        raise ValueError("an integration already uses this integration_id")
    manifest.setdefault("integrations", []).append(
        {
            "integration_id": validation["integration_id"],
            "file": filename,
            "sha256": digest,
            "job_id": job_dir.name,
            "approved_at": utc_now(),
            "dhcp_status": False,
        }
    )
    _atomic_json(manifest_path, manifest)
    manifest_path.chmod(0o600)
    return update_job(
        job_dir,
        "script_ready",
        "Codex desactivó y verificó la Wi-Fi. La integración quedó registrada.",
        validation=validation,
        approved_file=str(destination),
        sha256=digest,
    )


def _redact_secret(path: Path, secret: str) -> None:
    if not secret or not path.is_file():
        return
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return
    if secret in content:
        path.write_text(content.replace(secret, "[REDACTED]"), encoding="utf-8")


def discard_job_credentials(
    job_id: str,
    credentials_dir: Path = DEFAULT_CREDENTIALS_DIR,
) -> None:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        return
    (Path(credentials_dir) / f"{job_id}.json").unlink(missing_ok=True)


def run_job(
    job_id: str,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    project_dir: Path = DEFAULT_PROJECT_DIR,
    codex_binary: str = "/usr/bin/codex",
    credentials_dir: Path = DEFAULT_CREDENTIALS_DIR,
    integrations_dir: Optional[Path] = None,
    timeout: int = 1800,
) -> Dict:
    state_dir = Path(state_dir)
    job_dir = _job_dir(state_dir, job_id)
    request_data = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    credentials_path = Path(credentials_dir) / f"{job_id}.json"
    password = ""
    wifi_secret = ""
    credential_data = {}
    try:
        if credentials_path.is_file():
            credential_data = json.loads(credentials_path.read_text(encoding="utf-8"))
            password = credential_data.get("password") or ""
            wifi_secret = credential_data.get("wifi_password") or ""
        update_job(job_dir, "collecting_evidence", "Recopilando recursos públicos mediante GET.")
        collect_public_evidence(request_data["base_url"], job_dir / "workspace" / "evidence")
        workspace = prepare_workspace(job_dir, Path(project_dir), request_data["mode"])
        prompt = build_prompt(request_data, credentials_path)
        (workspace / "prompt.md").write_text(prompt, encoding="utf-8")
        update_job(
            job_dir,
            "running_codex",
            "Codex está inspeccionando el router sin modificarlo.",
        )
        command = [
            codex_binary,
            "--ask-for-approval",
            "never",
            "exec",
            "--sandbox",
            "workspace-write",
            "--config",
            "sandbox_workspace_write.network_access=true",
            "--ephemeral",
            "--ignore-user-config",
            "--skip-git-repo-check",
            "--json",
            "-",
        ]
        with (
            (job_dir / "events.jsonl").open("w", encoding="utf-8") as events,
            (job_dir / "codex.stderr.log").open("w", encoding="utf-8") as errors,
        ):
            result = subprocess.run(
                command,
                cwd=workspace,
                input=prompt,
                text=True,
                stdout=events,
                stderr=errors,
                timeout=timeout,
                check=False,
            )
        if result.returncode != 0:
            return update_job(
                job_dir,
                "failed",
                f"Codex terminó con código {result.returncode}.",
            )
        # Never rewrite executable candidate files: a short password may be a
        # legitimate substring of identifiers such as ``username``. Candidate
        # code remains private and requires explicit administrator review.
        for path in (
            job_dir / "events.jsonl",
            job_dir / "codex.stderr.log",
        ):
            _redact_secret(path, password)
            _redact_secret(path, wifi_secret)
        validation = validate_script_candidate(
            workspace / "candidate",
            target_base_url=request_data["base_url"],
            username=credential_data.get("username") or None,
            password=password,
        )
        if not validation["valid"]:
            return update_job(
                job_dir,
                "failed_validation",
                "La integración directa no superó la validación final.",
                validation=validation,
            )
        promoted = promote_script_candidate(
            job_dir,
            state_dir,
            validation,
            integrations_dir=integrations_dir,
        )
        ssid = credential_data.get("ssid") or ""
        wifi_password = credential_data.get("wifi_password") or ""
        if not ssid or not wifi_password:
            return promoted
        update_job(
            job_dir,
            "completing_setup",
            "Integración registrada. Configurando automáticamente la Raspberry...",
            validation=validation,
        )
        if not complete_setup_after_discovery(ssid, wifi_password):
            return update_job(
                job_dir,
                "setup_failed",
                "La Wi-Fi del router se desactivó, pero OpenWrt no completó el modo NORMAL.",
                validation=validation,
            )
        return update_job(
            job_dir,
            "completed",
            "Router integrado y migración completada automáticamente.",
            validation=validation,
        )
    except (OSError, requests.RequestException, subprocess.SubprocessError, ValueError) as error:
        return update_job(job_dir, "failed", str(error))
    finally:
        for path in (
            job_dir / "events.jsonl",
            job_dir / "codex.stderr.log",
        ):
            _redact_secret(path, password)
            _redact_secret(path, wifi_secret)
        discard_job_credentials(job_id, credentials_dir)
        password = ""
        wifi_secret = ""


def complete_setup_after_discovery(ssid: str, wifi_password: str) -> bool:
    """Import the portal lazily and reuse its verified NORMAL transition."""
    from setup_portal import finalize_script_takeover

    return finalize_script_takeover(ssid, wifi_password)


def _load_candidate_type(candidate: Path, job_id: str):
    module_name = f"tfg_candidate_{job_id}"
    spec = importlib.util.spec_from_file_location(module_name, candidate)
    if spec is None or spec.loader is None:
        raise ValueError("candidate module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from router_adapters import RouterAdapter

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
        raise ValueError("candidate must expose exactly one adapter class")
    return candidates[0]


def validate_candidate_read_only(
    job_id: str,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    username: Optional[str] = None,
    password: str,
) -> Dict:
    """Exercise a generated adapter against the router without changing it."""
    state_dir = Path(state_dir)
    job_dir = _job_dir(state_dir, job_id)
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    request_data = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    validation = validate_candidate(candidate, target_base_url=request_data["base_url"])
    if not validation["valid"] or not validation["hardware_test_ready"]:
        raise ValueError("candidate is not ready for live validation")

    adapter_type = _load_candidate_type(candidate, job_id)
    adapter = adapter_type(request_data["base_url"])
    detection = adapter.detect()
    if not detection.applies or detection.adapter != validation["adapter_id"]:
        raise ValueError("candidate did not detect the target router")

    from router_adapters import Credentials, FeatureState

    adapter.authenticate(Credentials(password=password, username=username))
    observed = adapter.get_status()
    if observed.wifi is FeatureState.UNKNOWN:
        raise ValueError("candidate could not read the Wi-Fi state")
    return {
        "adapter_id": validation["adapter_id"],
        "wifi": observed.wifi.value,
        "dhcp": observed.dhcp.value,
    }


def approve_job(
    job_id: str,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
) -> Dict:
    state_dir = Path(state_dir)
    job_dir = _job_dir(state_dir, job_id)
    status = read_job(job_id, state_dir)
    if status.get("status") != "awaiting_approval":
        raise ValueError("job is not awaiting approval")
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    request_data = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    validation = validate_candidate(
        candidate,
        target_base_url=request_data["base_url"],
    )
    if not validation["valid"]:
        raise ValueError("candidate no longer passes validation")
    if not validation["hardware_test_ready"]:
        raise ValueError("candidate is not ready for a Wi-Fi hardware test")

    return update_job(
        job_dir,
        "approved_for_hardware_test",
        "Revisión aceptada. Falta una prueba hardware explícita antes de registrarlo.",
        validation=validation,
    )


def _promote_candidate(
    job_dir: Path,
    state_dir: Path,
    validation: Dict,
    approved_dir: Optional[Path] = None,
) -> Dict:
    job_id = job_dir.name
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    content = candidate.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    approved_dir = (
        Path(approved_dir)
        if approved_dir is not None
        else Path(state_dir) / "approved"
    )
    approved_dir.mkdir(parents=True, exist_ok=True)
    approved_dir.chmod(0o700)
    filename = f"{job_id}-{validation['adapter_id']}.py"
    destination = approved_dir / filename
    destination.write_bytes(content)
    destination.chmod(0o600)

    manifest_path = approved_dir / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_path.exists()
        else {"adapters": []}
    )
    if any(item["adapter_id"] == validation["adapter_id"] for item in manifest["adapters"]):
        destination.unlink(missing_ok=True)
        raise ValueError("an approved adapter already uses this adapter_id")
    manifest["adapters"].append(
        {
            "adapter_id": validation["adapter_id"],
            "file": filename,
            "sha256": digest,
            "job_id": job_id,
            "approved_at": utc_now(),
        }
    )
    _atomic_json(manifest_path, manifest)
    manifest_path.chmod(0o600)
    return update_job(
        job_dir,
        "approved",
        "Adaptador aprobado y disponible para futuras detecciones.",
        approved_file=str(destination),
        sha256=digest,
    )


def apply_candidate_job(
    job_id: str,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    username: Optional[str] = None,
    password: str,
    approved_dir: Optional[Path] = None,
    verify_attempts: int = 7,
    verify_delay: float = 5.0,
) -> Dict:
    """Disable Wi-Fi with a candidate, verify convergence, then register it."""
    state_dir = Path(state_dir)
    job_dir = _job_dir(state_dir, job_id)
    status = read_job(job_id, state_dir)
    if status.get("status") != "ready_for_migration":
        raise ValueError("job is not ready for migration")
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    request_data = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    validation = validate_candidate(candidate, target_base_url=request_data["base_url"])
    if not validation["valid"] or not validation["hardware_test_ready"]:
        raise ValueError("candidate no longer passes validation")

    update_job(
        job_dir,
        "applying_wifi",
        "Desactivando la Wi-Fi del router con el adaptador candidato...",
        validation=validation,
    )
    secret = password
    try:
        adapter_type = _load_candidate_type(candidate, job_id)
        adapter = adapter_type(request_data["base_url"])
        detection = adapter.detect()
        if not detection.applies or detection.adapter != validation["adapter_id"]:
            raise ValueError("candidate did not detect the target router")

        from router_adapters import Credentials, FeatureState

        adapter.authenticate(Credentials(password=secret, username=username))
        before = adapter.get_status()
        if before.wifi is FeatureState.UNKNOWN:
            raise ValueError("candidate could not read Wi-Fi before the change")
        if before.wifi is FeatureState.ENABLED:
            operation = adapter.disable_wifi()
            if not operation.success:
                raise ValueError("candidate did not confirm the Wi-Fi write")

        verification = None
        for attempt in range(max(1, verify_attempts)):
            verification = adapter.verify(wifi=FeatureState.DISABLED)
            if verification.success:
                break
            if attempt + 1 < verify_attempts:
                time.sleep(max(0.0, verify_delay))
        if verification is None or not verification.success:
            raise ValueError("candidate did not verify Wi-Fi as disabled")
    except Exception as error:
        update_job(job_dir, "hardware_test_failed", str(error), validation=validation)
        raise
    finally:
        secret = None
    return _promote_candidate(
        job_dir,
        state_dir,
        validation,
        approved_dir=approved_dir,
    )


def hardware_test_job(
    job_id: str,
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    username: Optional[str] = None,
    password: Optional[str] = None,
    approved_dir: Optional[Path] = None,
    confirm_disable_wifi: bool = False,
) -> Dict:
    if not confirm_disable_wifi:
        raise ValueError("--confirm-disable-wifi is required")
    state_dir = Path(state_dir)
    job_dir = _job_dir(state_dir, job_id)
    status = read_job(job_id, state_dir)
    if status.get("status") != "approved_for_hardware_test":
        raise ValueError("job is not approved for hardware testing")
    candidate = job_dir / "workspace" / "candidate" / "adapter.py"
    request_data = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    validation = validate_candidate(
        candidate,
        target_base_url=request_data["base_url"],
    )
    if not validation["valid"]:
        raise ValueError("candidate no longer passes validation")
    if not validation["hardware_test_ready"]:
        raise ValueError("candidate is not ready for a Wi-Fi hardware test")
    secret = password if password is not None else getpass.getpass("Contraseña del router: ")
    try:
        adapter_type = _load_candidate_type(candidate, job_id)
        adapter = adapter_type(request_data["base_url"])
        detection = adapter.detect()
        if not detection.applies or detection.adapter != validation["adapter_id"]:
            raise ValueError("candidate did not detect the target router")
        from router_adapters import Credentials, FeatureState

        adapter.authenticate(Credentials(password=secret, username=username))
        before = adapter.get_status()
        if before.wifi is not FeatureState.ENABLED:
            raise ValueError("Wi-Fi must be observed enabled before the hardware test")
        operation = adapter.disable_wifi()
        if not operation.success:
            raise ValueError("candidate did not confirm the Wi-Fi write")
        verification = adapter.verify(wifi=FeatureState.DISABLED)
        if not verification.success:
            raise ValueError("candidate did not verify Wi-Fi as disabled")
    except Exception as error:
        update_job(job_dir, "hardware_test_failed", str(error))
        raise
    finally:
        secret = None
    return _promote_candidate(
        job_dir,
        state_dir,
        validation,
        approved_dir=approved_dir,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Descubrimiento de routers con Codex")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--approved-dir", default=str(DEFAULT_APPROVED_DIR))
    parser.add_argument("--integrations-dir", default=str(DEFAULT_INTEGRATIONS_DIR))
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("base_url")
    create_parser.add_argument("--mode", choices=sorted(DISCOVERY_MODES), default="clean_room")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("job_id")
    run_parser.add_argument("--project-dir", default=str(DEFAULT_PROJECT_DIR))
    run_parser.add_argument("--codex-binary", default="/usr/bin/codex")
    run_parser.add_argument("--credentials-dir", default=str(DEFAULT_CREDENTIALS_DIR))
    run_parser.add_argument("--timeout", type=int, default=1800)
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("job_id")
    hardware_parser = subparsers.add_parser("hardware-test")
    hardware_parser.add_argument("job_id")
    hardware_parser.add_argument("--username")
    hardware_parser.add_argument("--confirm-disable-wifi", action="store_true")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("job_id")
    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir)
    if args.command == "create":
        output = create_job(args.base_url, mode=args.mode, state_dir=state_dir)
    elif args.command == "run":
        output = run_job(
            args.job_id,
            state_dir=state_dir,
            project_dir=Path(args.project_dir),
            codex_binary=args.codex_binary,
            credentials_dir=Path(args.credentials_dir),
            integrations_dir=Path(args.integrations_dir),
            timeout=args.timeout,
        )
    elif args.command == "approve":
        output = approve_job(args.job_id, state_dir=state_dir)
    elif args.command == "hardware-test":
        output = hardware_test_job(
            args.job_id,
            state_dir=state_dir,
            approved_dir=Path(args.approved_dir),
            username=args.username,
            confirm_disable_wifi=args.confirm_disable_wifi,
        )
    else:
        output = read_job(args.job_id, state_dir)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
