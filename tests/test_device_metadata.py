import json

import pytest

from device_metadata import load_device_aliases, normalize_alias, update_device_alias


MAC = "02:00:00:00:00:01"


def test_alias_is_normalized_persisted_and_removed_atomically(tmp_path):
    path = tmp_path / "aliases.json"

    assert update_device_alias(MAC, "  Televisor   salón  ", path) == (
        "Televisor salón"
    )
    assert load_device_aliases(path) == {MAC: "Televisor salón"}
    assert json.loads(path.read_text(encoding="utf-8")) == {
        MAC: "Televisor salón"
    }

    assert update_device_alias(MAC, "", path) is None
    assert load_device_aliases(path) == {}


def test_invalid_aliases_and_macs_are_rejected_without_writing(tmp_path):
    path = tmp_path / "aliases.json"

    with pytest.raises(ValueError, match="64"):
        update_device_alias(MAC, "x" * 65, path)
    with pytest.raises(ValueError, match="MAC"):
        update_device_alias("not-a-mac", "Televisor", path)

    assert not path.exists()


def test_loading_aliases_ignores_invalid_document_entries(tmp_path):
    path = tmp_path / "aliases.json"
    path.write_text(
        json.dumps({MAC: "TV", "not-a-mac": "Router", "aa:bb:cc:dd:ee:ff": 0}),
        encoding="utf-8",
    )

    assert load_device_aliases(path) == {MAC: "TV"}


def test_normalize_alias_rejects_control_characters():
    with pytest.raises(ValueError, match="caracteres"):
        normalize_alias("TV\x00salón")
