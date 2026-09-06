"""Observación de la aplicación efectiva de políticas en nftables."""

import json
import re
import subprocess


TABLE_SPECS = {
    "l2": {
        "family": "netdev",
        "table": "tfg_l2",
        "sets": {
            "peer_allowed_macs",
            "mdns_allowed_macs",
            "ssdp_allowed_macs",
            "discovery_allowed_macs",
            "broadcast_allowed_macs",
            "broadcast_logged_macs",
        },
    },
    "l3": {
        "family": "inet",
        "table": "tfg_l3",
        "sets": {
            "internet_blocked_ips",
            "peer_allowed_ips",
        },
    },
}


def _element_values(value):
    if isinstance(value, (str, int, float)):
        return {str(value).lower()}
    if isinstance(value, list):
        result = set()
        for item in value:
            result.update(_element_values(item))
        return result
    if isinstance(value, dict):
        for key in ("val", "elem"):
            if key in value:
                return _element_values(value[key])
    return set()


def _extract_sets(document):
    sets = {}
    entries = document.get("nftables", []) if isinstance(document, dict) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        definition = entry.get("set")
        if isinstance(definition, dict) and definition.get("name"):
            name = definition["name"]
            sets.setdefault(name, set()).update(
                _element_values(definition.get("elem", []))
            )
        elements = entry.get("element")
        if isinstance(elements, dict) and elements.get("name"):
            name = elements["name"]
            sets.setdefault(name, set()).update(
                _element_values(elements.get("elem", []))
            )
    return sets


def _extract_text_sets(output):
    """Extrae conjuntos escalares de la salida legible de nft."""
    sets = {}
    current_name = None
    current_lines = []
    depth = 0
    for line in output.splitlines():
        if current_name is None:
            match = re.match(r"\s*set\s+([a-zA-Z0-9_]+)\s*\{", line)
            if not match:
                continue
            current_name = match.group(1)
            current_lines = [line]
            depth = line.count("{") - line.count("}")
        else:
            current_lines.append(line)
            depth += line.count("{") - line.count("}")
        if current_name is not None and depth == 0:
            body = "\n".join(current_lines)
            elements = re.search(r"elements\s*=\s*\{(.*?)\}", body, re.S)
            values = set()
            if elements:
                values = {
                    value.strip().strip('"').lower()
                    for value in elements.group(1).split(",")
                    if value.strip()
                }
            sets[current_name] = values
            current_name = None
            current_lines = []
    return sets


def _run_nft(run, command):
    return run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )


def _read_table_sets(run, nft_binary, specification):
    base_command = [
        nft_binary,
        "list",
        "table",
        specification["family"],
        specification["table"],
    ]
    try:
        result = _run_nft(run, [nft_binary, "-j", *base_command[1:]])
        if result.returncode == 0:
            try:
                return _extract_sets(json.loads(result.stdout)), None
            except (TypeError, ValueError):
                pass

        result = _run_nft(run, base_command)
        if result.returncode == 0:
            return _extract_text_sets(result.stdout), None
        return None, f"nft devolvió {result.returncode}"
    except (OSError, subprocess.SubprocessError) as error:
        return None, str(error)


def read_policy_snapshot(nft_binary="nft", run=None):
    """Obtiene una instantánea consistente y de solo lectura de las tablas."""
    run = subprocess.run if run is None else run
    snapshot = {"available": True, "tables": {}, "sets": {}, "error": None}
    errors = []
    for key, specification in TABLE_SPECS.items():
        table_sets, table_error = _read_table_sets(
            run, nft_binary, specification
        )
        if table_sets is None:
            snapshot["tables"][key] = False
            errors.append(f"{key}: {table_error}")
            continue
        missing = specification["sets"] - set(table_sets)
        if missing:
            snapshot["tables"][key] = False
            errors.append(f"{key}: faltan conjuntos {', '.join(sorted(missing))}")
            continue
        snapshot["tables"][key] = True
        snapshot["sets"].update(table_sets)

    snapshot["available"] = all(snapshot["tables"].values())
    if errors:
        snapshot["error"] = "; ".join(errors)
    return snapshot


def _control(configured, effective, available=True):
    if not available:
        status = "unavailable"
    elif configured == effective:
        status = "applied"
    else:
        status = "different"
    return {
        "configured": configured,
        "effective": effective if available else None,
        "status": status,
    }


def _inactive_policy(policy):
    configured_controls = dict(policy)
    configured_controls["discovery"] = bool(
        policy.get("mdns") or policy.get("ssdp")
    )
    return {
        "status": "inactive",
        "differences": [],
        "error": None,
        "controls": {
            name: {
                "configured": value,
                "effective": None,
                "status": "inactive",
            }
            for name, value in configured_controls.items()
        },
    }


def evaluate_device_policy(device, snapshot):
    """Compara una política configurada con los conjuntos nft observados."""
    policy = device.get("policy", {})
    if not device.get("created"):
        return _inactive_policy(policy)
    if not snapshot.get("available"):
        result = _inactive_policy(policy)
        result["status"] = "unavailable"
        result["error"] = snapshot.get("error")
        return result

    mac = str(device.get("mac") or "").lower()
    address = str(device.get("ip") or "").lower()
    sets = snapshot["sets"]
    if not mac or not address or address == "sin asignar":
        result = _inactive_policy(policy)
        result["status"] = "unavailable"
        result["error"] = "El dispositivo activo no tiene MAC o IP válida."
        return result

    peer_mac = mac in sets["peer_allowed_macs"]
    peer_ip = address in sets["peer_allowed_ips"]
    if peer_mac == peer_ip:
        peer_control = _control(policy.get("inter_device"), peer_mac)
    else:
        peer_control = {
            "configured": policy.get("inter_device"),
            "effective": None,
            "status": "different",
        }
    discovery_configured = bool(policy.get("mdns") or policy.get("ssdp"))
    discovery_effective = mac in sets["discovery_allowed_macs"]
    broadcast_allowed = mac in sets["broadcast_allowed_macs"]
    broadcast_logged = mac in sets["broadcast_logged_macs"]
    if broadcast_allowed and broadcast_logged:
        broadcast = "conflict"
    elif broadcast_allowed:
        broadcast = "allow"
    elif broadcast_logged:
        broadcast = "log"
    else:
        broadcast = "block"

    controls = {
        "internet": _control(
            policy.get("internet"), address not in sets["internet_blocked_ips"]
        ),
        "inter_device": peer_control,
        "mdns": _control(
            policy.get("mdns"),
            mac in sets["mdns_allowed_macs"],
        ),
        "ssdp": _control(
            policy.get("ssdp"),
            mac in sets["ssdp_allowed_macs"],
        ),
        "discovery": _control(discovery_configured, discovery_effective),
        "broadcast": _control(policy.get("broadcast"), broadcast),
    }
    differences = [
        name for name, control in controls.items()
        if control["status"] == "different"
    ]
    return {
        "status": "different" if differences else "applied",
        "differences": differences,
        "error": None,
        "controls": controls,
    }


def load_policy_application(devices, nft_binary="nft", run=None):
    """Devuelve la aplicación efectiva para todos los dispositivos."""
    if not any(device.get("created") for device in devices):
        return {
            str(device.get("mac") or "").lower(): _inactive_policy(
                device.get("policy", {})
            )
            for device in devices
            if device.get("mac")
        }
    snapshot = read_policy_snapshot(nft_binary=nft_binary, run=run)
    return {
        str(device.get("mac") or "").lower(): evaluate_device_policy(
            device, snapshot
        )
        for device in devices
        if device.get("mac")
    }
