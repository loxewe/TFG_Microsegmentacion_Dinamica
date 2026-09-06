"""Alias de dispositivos administrados por la interfaz web."""

import json
import os
from pathlib import Path
import re
import tempfile
import threading


MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_ALIAS_LENGTH = 64
_LOCK = threading.RLock()


def normalize_alias(value):
    """Valida un alias visible; una cadena vacía elimina el alias actual."""
    alias = " ".join(str(value or "").split())
    if not alias:
        return None
    if len(alias) > MAX_ALIAS_LENGTH:
        raise ValueError("El alias no puede superar 64 caracteres.")
    if not all(character.isprintable() for character in alias):
        raise ValueError("El alias contiene caracteres no válidos.")
    return alias


def load_device_aliases(path):
    """Carga únicamente entradas MAC/alias válidas de un archivo opcional."""
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError):
        return {}
    if not isinstance(document, dict):
        return {}

    aliases = {}
    for mac, value in document.items():
        normalized_mac = str(mac).lower()
        if not MAC_PATTERN.fullmatch(normalized_mac):
            continue
        try:
            alias = normalize_alias(value)
        except ValueError:
            continue
        if alias:
            aliases[normalized_mac] = alias
    return aliases


def update_device_alias(mac, value, path):
    """Guarda o elimina un alias mediante reemplazo atómico del archivo."""
    normalized_mac = str(mac or "").lower()
    if not MAC_PATTERN.fullmatch(normalized_mac):
        raise ValueError("La dirección MAC no es válida.")
    alias = normalize_alias(value)
    path = Path(path)

    with _LOCK:
        aliases = load_device_aliases(path)
        if alias is None:
            aliases.pop(normalized_mac, None)
        else:
            aliases[normalized_mac] = alias

        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", text=True
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(aliases, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    return alias


def remove_device_aliases(macs, path):
    """Elimina en una sola escritura los alias de las MAC indicadas."""
    normalized_macs = set()
    for mac in macs:
        normalized_mac = str(mac or "").lower()
        if not MAC_PATTERN.fullmatch(normalized_mac):
            raise ValueError("La dirección MAC no es válida.")
        normalized_macs.add(normalized_mac)

    path = Path(path)
    with _LOCK:
        aliases = load_device_aliases(path)
        for mac in normalized_macs:
            aliases.pop(mac, None)

        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", text=True
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(aliases, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
