"""Mercusys MR1500X adapter for the encrypted LuCI web API."""

import base64
import hashlib
import json
import os
import random
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ..base import RouterAdapter
from ..errors import AdapterAuthenticationError, AdapterProtocolError
from ..models import (
    AdapterCapabilities,
    AdapterMaturity,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterStatus,
)


WIFI_PATH = "/admin/wireless?form=wireless_2g&form=wireless_5g"
DHCP_PATH = "/admin/dhcps?form=setting"
WIFI_WRITE_DEFAULTS = {
    "wireless_2g_transmitPowerDisable": "",
    "wireless_2g_hwmode": "bgn",
    "wireless_2g_htmode": "auto",
    "wireless_2g_channel": "auto",
    "wireless_2g_txpower": "high",
    "wireless_5g_transmitPowerDisable": "",
    "wireless_5g_hwmode": "anacax_5",
    "wireless_5g_htmode": "80",
    "wireless_5g_channel": "auto",
    "wireless_5g_txpower": "high",
    "wireless_5g_mu_mimo": "on",
}


def _rsa_encrypt(text: str, modulus: str, exponent: str = "010001") -> str:
    n = int(modulus, 16)
    e = int(exponent, 16)
    size = (n.bit_length() + 7) // 8
    raw = text.encode("utf-8")
    padding = bytearray()
    while len(padding) < size - len(raw) - 3:
        byte = os.urandom(1)
        if byte != b"\0":
            padding.extend(byte)
    encoded = b"\0\2" + bytes(padding) + b"\0" + raw
    return pow(int.from_bytes(encoded, "big"), e, n).to_bytes(size, "big").hex()


def _rsa_chunks(text: str, modulus: str, exponent: str = "010001") -> str:
    return "".join(
        _rsa_encrypt(text[position : position + 53], modulus, exponent)
        for position in range(0, len(text), 53)
    )


class MercusysMR1500XAdapter(RouterAdapter):
    """Stateful client for MR1500X v2 firmware using RSA and AES-CBC."""

    adapter_id = "mercusys-mr1500x"
    maturity = AdapterMaturity.EXPERIMENTAL
    capabilities = AdapterCapabilities()

    def __init__(self, base_url: str = "http://192.168.0.1"):
        super().__init__(base_url)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        self._stok: Optional[str] = None
        self._key: Optional[str] = None
        self._iv: Optional[str] = None
        self._auth_hash: Optional[str] = None
        self._sequence: Optional[int] = None
        self._sign_modulus: Optional[str] = None
        self._sign_exponent: Optional[str] = None
        self._dhcp_restore_payload: Optional[Dict[str, Any]] = None

    def _public_read(self, form: str) -> Dict[str, Any]:
        try:
            response = self.session.post(
                self.base_url + "/cgi-bin/luci/;stok=" + form,
                data={"operation": "read"},
                timeout=5,
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AdapterProtocolError(str(exc)) from exc

    def detect(self) -> DetectionResult:
        device = self._public_read("/login?form=get_deviceInfo")
        firmware = self._public_read("/login?form=get_firmware_info")
        keys = self._public_read("/login?form=keys")
        model = device.get("data", {}).get("model")
        key_data = keys.get("data", {}).get("password", [])
        applies = model == "MR1500X" and len(key_data) == 2
        return DetectionResult(
            applies=applies,
            adapter=self.adapter_id,
            variant=firmware.get("data", {}).get("hardware_version"),
            confidence=1.0 if applies else 0.0,
            evidence={
                "model": model,
                "firmware": firmware.get("data", {}).get("firmware_version"),
                "rsa_login_key": len(key_data) == 2,
            },
        )

    def authenticate(self, credentials: Credentials) -> None:
        try:
            password_key = self._public_read("/login?form=keys")["data"][
                "password"
            ]
            auth = self._public_read("/login?form=auth")["data"]
            encrypted_password = _rsa_chunks(
                credentials.password, password_key[0], password_key[1]
            )
            stamp = str(int(time.time() * 1000))
            self._key = (stamp + str(random.randrange(10**9)).zfill(9))[:16]
            self._iv = (stamp + str(random.randrange(10**9)).zfill(9))[:16]
            self._sequence = int(auth["seq"])
            self._sign_modulus, self._sign_exponent = auth["key"]
            self._auth_hash = hashlib.md5(
                ("admin" + credentials.password).encode("utf-8")
            ).hexdigest()
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterAuthenticationError("invalid authentication metadata") from exc

        clear = (
            "password="
            + urllib.parse.quote(encrypted_password)
            + "&operation=login"
        )
        encrypted = self._aes_encrypt(clear)
        signature = _rsa_chunks(
            f"k={self._key}&i={self._iv}&h={self._auth_hash}"
            f"&s={self._sequence + len(encrypted)}",
            self._sign_modulus,
            self._sign_exponent,
        )
        try:
            response = self.session.post(
                self.base_url + "/cgi-bin/luci/;stok=/login?form=login",
                data={"sign": signature, "data": encrypted},
                timeout=8,
            )
            response.raise_for_status()
            clear_response = json.loads(self._aes_decrypt(response.json()["data"]))
            self._stok = clear_response["data"]["stok"]
        except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
            raise AdapterAuthenticationError("login response was rejected") from exc

    def _aes_encrypt(self, clear: str) -> str:
        cipher = AES.new(self._key.encode(), AES.MODE_CBC, self._iv.encode())
        encrypted = cipher.encrypt(pad(clear.encode(), AES.block_size))
        return base64.b64encode(encrypted).decode()

    def _aes_decrypt(self, encrypted: str) -> str:
        cipher = AES.new(self._key.encode(), AES.MODE_CBC, self._iv.encode())
        clear = cipher.decrypt(base64.b64decode(encrypted))
        return unpad(clear, AES.block_size).decode()

    def _operation(
        self, path: str, fields: Dict[str, Any], action: str
    ) -> Dict[str, Any]:
        if not self._stok:
            raise AdapterAuthenticationError("authenticate must be called first")
        clear = urllib.parse.urlencode(fields)
        encrypted = self._aes_encrypt(clear)
        signature = _rsa_chunks(
            f"h={self._auth_hash}&s={self._sequence + len(encrypted)}",
            self._sign_modulus,
            self._sign_exponent,
        )
        try:
            response = self.session.post(
                self.base_url + "/cgi-bin/luci/;stok=" + self._stok + path,
                data={"sign": signature, "data": encrypted},
                timeout=8,
            )
            response.raise_for_status()
            return json.loads(self._aes_decrypt(response.json()["data"]))
        except (requests.RequestException, KeyError, ValueError, TypeError) as exc:
            raise AdapterProtocolError(f"could not decode {action} response") from exc

    def _read_operation(self, path: str) -> Dict[str, Any]:
        return self._operation(path, {"operation": "read"}, "read")

    def _write_operation(
        self, path: str, fields: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self._operation(path, fields, "write")

    def _read_wifi(self) -> Dict[str, Any]:
        return self._read_operation(WIFI_PATH)

    def _read_dhcp(self) -> Dict[str, Any]:
        return self._read_operation(DHCP_PATH)

    @staticmethod
    def _states(wifi_data, dhcp_data):
        radio_values = [
            wifi_data.get("wireless_2g_enable"),
            wifi_data.get("wireless_5g_enable"),
        ]
        wifi_state = (
            FeatureState.ENABLED
            if "on" in radio_values
            else FeatureState.DISABLED
            if all(value == "off" for value in radio_values)
            else FeatureState.UNKNOWN
        )
        dhcp_state = {
            "on": FeatureState.ENABLED,
            "off": FeatureState.DISABLED,
            True: FeatureState.ENABLED,
            False: FeatureState.DISABLED,
        }.get(dhcp_data.get("enable"), FeatureState.UNKNOWN)
        return wifi_state, dhcp_state

    def get_status(self) -> RouterStatus:
        wifi_data = self._read_wifi().get("data", {})
        dhcp_data = self._read_dhcp().get("data", {})
        wifi_state, dhcp_state = self._states(wifi_data, dhcp_data)
        # Only non-sensitive state indicators leave the adapter.
        details = {
            "wifi_2g": wifi_data.get("wireless_2g_enable"),
            "wifi_5g": wifi_data.get("wireless_5g_enable"),
            "dhcp": dhcp_data.get("enable"),
        }
        return RouterStatus(wifi=wifi_state, dhcp=dhcp_state, details=details)

    def disable_wifi(self) -> OperationResult:
        response = self._read_wifi()
        if response.get("success") is not True or not isinstance(
            response.get("data"), dict
        ):
            raise AdapterProtocolError(
                "Wi-Fi read did not return configuration data"
            )
        current = response["data"]
        if (
            current.get("wireless_2g_enable") == "off"
            and current.get("wireless_5g_enable") == "off"
        ):
            return OperationResult(
                success=True,
                changed=False,
                message="already disabled",
            )

        # The firmware rejects a dump of the complete read response. Build the
        # same small writable form used by its web UI and never resend SSIDs,
        # Wi-Fi keys or read-only metadata.
        payload = {
            field: current.get(field)
            if current.get(field) is not None
            else default
            for field, default in WIFI_WRITE_DEFAULTS.items()
        }
        payload.update(
            {
                "operation": "write_spf",
                "wireless_2g_enable": "off",
                "wireless_2g_disabled_all": "on",
                "wireless_5g_enable": "off",
                "wireless_5g_disabled_all": "on",
            }
        )
        result = self._write_operation(WIFI_PATH, payload)
        return OperationResult(
            success=result.get("success") is True,
            changed=True,
        )

    def _plan_disable_dhcp(self) -> Dict[str, Any]:
        response = self._read_dhcp()
        if response.get("success") is not True or not isinstance(
            response.get("data"), dict
        ):
            raise AdapterProtocolError("DHCP read did not return configuration data")
        current = dict(response["data"])
        if "enable" not in current:
            raise AdapterProtocolError("DHCP response has no enable field")

        self._dhcp_restore_payload = {"operation": "write", **current}
        planned = dict(self._dhcp_restore_payload)
        planned["enable"] = "off"
        changed = {
            key
            for key in planned
            if planned.get(key) != self._dhcp_restore_payload.get(key)
        }
        if changed - {"enable"}:
            raise AdapterProtocolError("DHCP plan changes fields other than enable")
        return planned

    def disable_dhcp(self) -> OperationResult:
        payload = self._plan_disable_dhcp()
        if self._dhcp_restore_payload["enable"] == "off":
            return OperationResult(
                success=True,
                changed=False,
                message="already disabled",
            )
        result = self._write_operation(DHCP_PATH, payload)
        return OperationResult(
            success=result.get("success") is True,
            changed=True,
        )

    def restore_dhcp(self) -> Dict[str, Any]:
        """Restore the in-memory DHCP snapshot after a failed verification."""
        if self._dhcp_restore_payload is None:
            raise AdapterProtocolError("no DHCP restore payload is available")
        result = self._write_operation(DHCP_PATH, self._dhcp_restore_payload)
        return {"success": result.get("success") is True, "restored": True}
