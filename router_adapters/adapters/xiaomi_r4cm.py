"""Xiaomi R4CM adapter discovered from the firmware's locally served web UI."""

import hashlib
import random
import re
import time
from typing import Any, Dict, Optional

import requests

from ..base import RouterAdapter
from ..errors import (
    AdapterAuthenticationError,
    AdapterProtocolError,
)
from ..models import (
    AdapterCapabilities,
    AdapterMaturity,
    Credentials,
    DetectionResult,
    FeatureState,
    OperationResult,
    RouterStatus,
)


LOGIN_PAGE_PATH = "/cgi-bin/luci/web"
LOGIN_API_PATH = "/cgi-bin/luci/api/xqsystem/login"
WIFI_STATUS_ENDPOINT = "xqnetwork/wifi_detail_all"
DHCP_STATUS_ENDPOINT = "xqnetwork/lan_dhcp"
DHCP_WRITE_ENDPOINT = "xqnetwork/set_lan_dhcp"


class XiaomiR4CMAdapter(RouterAdapter):
    """Stateful client for Xiaomi R4CM firmware 3.0.45's LuCI web API."""

    adapter_id = "xiaomi-r4cm"
    maturity = AdapterMaturity.APPROVED
    capabilities = AdapterCapabilities(
        wifi_status=True,
        dhcp_status=True,
        disable_wifi=True,
        disable_dhcp=True,
    )

    def __init__(self, base_url: str = "http://192.168.31.1"):
        super().__init__(base_url)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "router-adapter/xiaomi-r4cm",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            }
        )
        self._token: Optional[str] = None
        self._device_id: Optional[str] = None
        self._auth_key: Optional[str] = None
        self._wifi_restore_payload: Optional[Dict[str, Any]] = None

    def _get_login_page(self) -> str:
        try:
            response = self.session.get(
                self.base_url + LOGIN_PAGE_PATH,
                timeout=5,
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as exc:
            raise AdapterProtocolError(str(exc)) from exc

    def _load_login_metadata(self, body: str) -> None:
        device = re.search(r"deviceId\s*=\s*'([^']+)'", body)
        key = re.search(r"key:\s*'([^']+)'", body)
        if not device or not key:
            raise AdapterAuthenticationError(
                "login page does not expose the expected authentication metadata"
            )
        self._device_id = device.group(1)
        self._auth_key = key.group(1)

    def detect(self) -> DetectionResult:
        body = self._get_login_page()
        hardware = re.search(r"hardwareVersion:\s*'([^']+)'", body)
        firmware = re.search(r"romVersion:\s*'([^']+)'", body)
        channel = re.search(r"romChannel:\s*'([^']+)'", body)
        applies = "MiWi-Fi Router" in body and bool(
            hardware and hardware.group(1) == "R4CM"
        )
        return DetectionResult(
            applies=applies,
            adapter=self.adapter_id,
            variant=hardware.group(1) if hardware else None,
            confidence=1.0 if applies else 0.0,
            evidence={
                "manufacturer": "Xiaomi" if "MiWi-Fi Router" in body else "UNKNOWN",
                "model": hardware.group(1) if hardware else "UNKNOWN",
                "firmware": firmware.group(1) if firmware else "UNKNOWN",
                "channel": channel.group(1) if channel else "UNKNOWN",
            },
        )

    @staticmethod
    def _digest(password: str, nonce: str, key: str) -> str:
        inner = hashlib.sha1((password + key).encode("utf-8")).hexdigest()
        return hashlib.sha1((nonce + inner).encode("utf-8")).hexdigest()

    def authenticate(self, credentials: Credentials) -> None:
        body = self._get_login_page()
        self._load_login_metadata(body)
        nonce = "0_%s_%d_%d" % (
            self._device_id,
            int(time.time()),
            random.SystemRandom().randrange(10000),
        )
        payload = {
            "username": credentials.username or "admin",
            "password": self._digest(credentials.password, nonce, self._auth_key),
            "logtype": "2",
            "nonce": nonce,
        }
        try:
            response = self.session.post(
                self.base_url + LOGIN_API_PATH,
                data=payload,
                timeout=5,
            )
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AdapterAuthenticationError(str(exc)) from exc
        token = result.get("token") if isinstance(result, dict) else None
        if result.get("code") != 0 or not token:
            raise AdapterAuthenticationError(
                "login failed with code %r"
                % (result.get("code") if isinstance(result, dict) else None)
            )
        self._token = str(token)

    def _api_get(
        self, endpoint: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if not self._token:
            raise AdapterAuthenticationError("authenticate must be called first")
        url = "%s/cgi-bin/luci/;stok=%s/api/%s" % (
            self.base_url,
            self._token,
            endpoint.lstrip("/"),
        )
        try:
            response = self.session.get(url, params=params, timeout=5)
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AdapterProtocolError(str(exc)) from exc
        if not isinstance(result, dict) or result.get("code") != 0:
            raise AdapterProtocolError(
                "API returned code %r"
                % (result.get("code") if isinstance(result, dict) else None)
            )
        return result

    def _api_post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self._token:
            raise AdapterAuthenticationError("authenticate must be called first")
        url = "%s/cgi-bin/luci/;stok=%s/api/%s" % (
            self.base_url,
            self._token,
            endpoint.lstrip("/"),
        )
        try:
            response = self.session.post(url, data=data, timeout=5)
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AdapterProtocolError(str(exc)) from exc
        if not isinstance(result, dict) or result.get("code") != 0:
            raise AdapterProtocolError(
                "API returned code %r"
                % (result.get("code") if isinstance(result, dict) else None)
            )
        return result

    @staticmethod
    def _wifi_state(response: Dict[str, Any]) -> FeatureState:
        radios = response.get("info")
        if not isinstance(radios, list) or not radios:
            return FeatureState.UNKNOWN
        states = [radio.get("status") for radio in radios if isinstance(radio, dict)]
        if not states or any(state not in (0, 1, "0", "1") for state in states):
            return FeatureState.UNKNOWN
        if any(str(state) == "1" for state in states):
            return FeatureState.ENABLED
        return FeatureState.DISABLED

    @staticmethod
    def _dhcp_state(response: Dict[str, Any]) -> FeatureState:
        info = response.get("info")
        if not isinstance(info, dict):
            return FeatureState.UNKNOWN
        return {
            0: FeatureState.ENABLED,
            "0": FeatureState.ENABLED,
            1: FeatureState.DISABLED,
            "1": FeatureState.DISABLED,
        }.get(info.get("ignore"), FeatureState.UNKNOWN)

    def get_status(self) -> RouterStatus:
        wifi_response = self._api_get(WIFI_STATUS_ENDPOINT)
        dhcp_response = self._api_get(DHCP_STATUS_ENDPOINT)
        radios = wifi_response.get("info")
        radio_states = (
            [radio.get("status") for radio in radios if isinstance(radio, dict)]
            if isinstance(radios, list)
            else []
        )
        dhcp_info = dhcp_response.get("info")
        dhcp_ignore = (
            dhcp_info.get("ignore") if isinstance(dhcp_info, dict) else "UNKNOWN"
        )
        return RouterStatus(
            wifi=self._wifi_state(wifi_response),
            dhcp=self._dhcp_state(dhcp_response),
            details={
                "wifi_radio_statuses": radio_states,
                "dhcp_ignore": dhcp_ignore,
            },
        )

    @staticmethod
    def _pwddecode(value: Any) -> str:
        """Apply the exact single-pass entity replacements used by the UI."""
        decoded = str(value)
        for entity, character in (
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", '"'),
            ("&#039;", "'"),
        ):
            decoded = decoded.replace(entity, character, 1)
        return decoded

    @classmethod
    def _main_wifi_payload(
        cls, response: Dict[str, Any], *, enabled: bool
    ) -> Dict[str, Any]:
        radios = response.get("info")
        if not isinstance(radios, list) or not radios or not isinstance(radios[0], dict):
            raise AdapterProtocolError("Wi-Fi response has no primary 2.4 GHz entry")
        current = radios[0]
        required = (
            "ssid",
            "password",
            "encryption",
            "channel",
            "bandwidth",
            "hidden",
            "txpwr",
            "status",
        )
        missing = [field for field in required if field not in current]
        if missing:
            raise AdapterProtocolError(
                "primary Wi-Fi response lacks required fields: " + ", ".join(missing)
            )
        if current["status"] not in (0, 1, "0", "1"):
            raise AdapterProtocolError("primary Wi-Fi status has an unexpected value")
        return {
            "wifiIndex": "1",
            "on": "1" if enabled else "0",
            "ssid": str(current["ssid"]),
            "pwd": cls._pwddecode(current["password"]),
            "encryption": str(current["encryption"]),
            "channel": str(current["channel"]),
            "bandwidth": str(current["bandwidth"]),
            "hidden": "1" if current["hidden"] in (1, "1", True) else "0",
            "txpwr": str(current["txpwr"]),
        }

    @staticmethod
    def sanitize_wifi_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **payload,
            "ssid": "<REDACTED:PRESERVED>",
            "pwd": "<REDACTED:PRESERVED_AND_PWDDECODED>",
        }

    def plan_disable_wifi(self) -> Dict[str, Any]:
        """Read current 2.4 GHz config and retain a restorable snapshot in memory."""
        response = self._api_get(WIFI_STATUS_ENDPOINT)
        radios = response.get("info")
        if not isinstance(radios, list) or not radios or not isinstance(radios[0], dict):
            raise AdapterProtocolError("Wi-Fi response has no primary 2.4 GHz entry")
        current_status = radios[0].get("status")
        self._wifi_restore_payload = self._main_wifi_payload(
            response,
            enabled=str(current_status) == "1",
        )
        planned = dict(self._wifi_restore_payload)
        planned["on"] = "0"
        changed = {
            key
            for key in planned
            if planned.get(key) != self._wifi_restore_payload.get(key)
        }
        if changed - {"on"}:
            raise AdapterProtocolError("Wi-Fi plan changes fields other than on")
        return planned

    def _primary_wifi_state(self) -> FeatureState:
        response = self._api_get(WIFI_STATUS_ENDPOINT)
        radios = response.get("info")
        if not isinstance(radios, list) or not radios or not isinstance(radios[0], dict):
            return FeatureState.UNKNOWN
        return {
            0: FeatureState.DISABLED,
            "0": FeatureState.DISABLED,
            1: FeatureState.ENABLED,
            "1": FeatureState.ENABLED,
        }.get(radios[0].get("status"), FeatureState.UNKNOWN)

    def _wait_for_primary_wifi(
        self,
        expected: FeatureState,
        *,
        settle_seconds: float = 30.0,
        timeout: float = 15.0,
        interval: float = 2.0,
    ) -> FeatureState:
        """Honor the UI's 30-second Wi-Fi restart, then poll read-only state."""
        time.sleep(settle_seconds)
        deadline = time.monotonic() + timeout
        observed = FeatureState.UNKNOWN
        while True:
            observed = self._primary_wifi_state()
            if observed is expected or time.monotonic() >= deadline:
                return observed
            time.sleep(interval)

    def restore_wifi(self) -> Dict[str, Any]:
        if self._wifi_restore_payload is None:
            raise AdapterProtocolError("no in-memory Wi-Fi restore payload is available")
        expected = {
            "0": FeatureState.DISABLED,
            "1": FeatureState.ENABLED,
        }[self._wifi_restore_payload["on"]]
        self._api_post("xqnetwork/set_wifi", self._wifi_restore_payload)
        observed = self._wait_for_primary_wifi(expected)
        if observed is not expected:
            raise AdapterProtocolError("Wi-Fi rollback verification failed")
        return {"success": True, "restored": True}

    def disable_wifi(self) -> OperationResult:
        """Disable primary 2.4 GHz Wi-Fi, verify, and roll back on any failure."""
        preview = (
            dict(self._wifi_restore_payload)
            if self._wifi_restore_payload is not None
            else None
        )
        if preview is not None:
            preview["on"] = "0"
        planned = self.plan_disable_wifi()
        if preview is not None and planned != preview:
            raise AdapterProtocolError(
                "Wi-Fi configuration changed after preview; no write was attempted"
            )
        was_enabled = self._wifi_restore_payload["on"] == "1"
        try:
            self._api_post("xqnetwork/set_wifi", planned)
            observed = self._wait_for_primary_wifi(FeatureState.DISABLED)
            if observed is not FeatureState.DISABLED:
                raise AdapterProtocolError("primary 2.4 GHz Wi-Fi verification failed")
        except Exception as exc:
            try:
                self.restore_wifi()
            except Exception as rollback_exc:
                raise AdapterProtocolError(
                    "Wi-Fi disable failed and rollback could not be verified"
                ) from rollback_exc
            raise AdapterProtocolError(
                "Wi-Fi disable failed; previous state was restored and verified"
            ) from exc
        return OperationResult(
            success=True,
            changed=was_enabled,
            details={"primary_2g": "disabled"},
        )

    def disable_dhcp(self) -> OperationResult:
        result = self._api_get(DHCP_WRITE_ENDPOINT, {"ignore": "1"})
        return OperationResult(
            success=result.get("code") == 0,
            changed=True,
        )
