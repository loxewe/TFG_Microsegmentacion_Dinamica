"""GL.iNet JSON-RPC adapter, migrated from conmutar_glinet.py."""

import hashlib
from typing import Any, Dict

import requests
from passlib.hash import sha256_crypt

from ..base import RouterAdapter
from ..errors import (
    AdapterAuthenticationError,
    AdapterProtocolError,
    AdapterUnsupportedOperation,
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


class GLInetAdapter(RouterAdapter):
    adapter_id = "glinet"
    maturity = AdapterMaturity.APPROVED
    capabilities = AdapterCapabilities(
        wifi_status=True,
        dhcp_status=False,
        disable_wifi=True,
        disable_dhcp=False,
    )

    def __init__(self, base_url: str = "http://192.168.8.1"):
        super().__init__(base_url)
        self.rpc_url = self.base_url + "/rpc"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
            }
        )
        self._sid = None
        self._rpc_id = 0

    def _post(self, payload: Dict[str, Any], timeout=None) -> Dict[str, Any]:
        try:
            response = self.session.post(
                self.rpc_url, json=payload, verify=False, timeout=timeout
            )
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AdapterProtocolError(str(exc)) from exc

    def _next_id(self) -> int:
        self._rpc_id += 1
        return self._rpc_id

    def _challenge(self, username: str) -> Dict[str, Any]:
        return self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "challenge",
                "params": {"username": username},
            },
            timeout=5,
        )

    def detect(self) -> DetectionResult:
        data = self._challenge("root")
        result = data.get("result", {})
        applies = "nonce" in result and "salt" in result
        return DetectionResult(
            applies=applies,
            adapter=self.adapter_id,
            variant="glinet-rpc" if applies else None,
            confidence=0.95 if applies else 0.0,
            evidence={"rpc_challenge": applies},
        )

    def authenticate(self, credentials: Credentials) -> None:
        username = credentials.username or "root"
        challenge = self._challenge(username).get("result", {})
        try:
            shadow = sha256_crypt.using(
                salt=challenge["salt"], rounds=5000
            ).hash(credentials.password)
            response_hash = hashlib.sha256(
                f"{username}:{shadow}:{challenge['nonce']}".encode("utf-8")
            ).hexdigest()
        except KeyError as exc:
            raise AdapterAuthenticationError("invalid challenge response") from exc

        data = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "login",
                "params": {"username": username, "hash": response_hash},
            }
        )
        self._sid = data.get("result", {}).get("sid")
        if not self._sid:
            raise AdapterAuthenticationError("invalid credentials or login response")
        self.session.cookies.set("Admin-Token", self._sid)

    def _call(self, service: str, method: str, arguments: Dict[str, Any], timeout=None):
        if not self._sid:
            raise AdapterAuthenticationError("authenticate must be called first")
        data = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "call",
                "params": [self._sid, service, method, arguments],
            },
            timeout=timeout,
        )
        if "error" in data:
            raise AdapterProtocolError(str(data["error"]))
        return data.get("result")

    def get_status(self) -> RouterStatus:
        result = self._call("wifi", "get_config", {"iface_name": "wifi2g"}, 5)
        config = result if isinstance(result, dict) else {}
        enabled = config.get("enabled")
        if enabled is None and isinstance(config.get("config"), dict):
            enabled = config["config"].get("enabled")

        # GL-MT300N-V2 firmware returns the radio inventory under
        # result.res[].ifaces[] instead of placing enabled at the root.
        if enabled is None and isinstance(config.get("res"), list):
            for radio in config["res"]:
                if not isinstance(radio, dict):
                    continue
                ifaces = radio.get("ifaces")
                if not isinstance(ifaces, list):
                    continue
                for interface in ifaces:
                    if not isinstance(interface, dict):
                        continue
                    if (
                        interface.get("name") == "wifi2g"
                        and not interface.get("guest", False)
                    ):
                        enabled = interface.get("enabled")
                        break
                if enabled is not None:
                    break

        wifi = {
            True: FeatureState.ENABLED,
            False: FeatureState.DISABLED,
        }.get(enabled, FeatureState.UNKNOWN)
        return RouterStatus(
            wifi=wifi,
            dhcp=FeatureState.UNKNOWN,
            # Some firmwares include SSIDs and Wi-Fi keys in get_config.
            details={"wifi2g": {"enabled": enabled}},
        )

    def disable_wifi(self) -> OperationResult:
        # Same service, method, interface and value as the existing script.
        try:
            self._call(
                "wifi",
                "set_config",
                {"iface_name": "wifi2g", "enabled": False},
                timeout=5,
            )
        except AdapterProtocolError as exc:
            # Preserves the switcher's behaviour: losing the connection while
            # disabling the radio is expected after the request was sent.
            if isinstance(exc.__cause__, requests.RequestException):
                return OperationResult(
                    success=True,
                    changed=True,
                    message="connection closed after Wi-Fi write",
                )
            raise
        return OperationResult(success=True, changed=True)

    def disable_dhcp(self) -> OperationResult:
        raise AdapterUnsupportedOperation(
            "this GL.iNet firmware's DHCP RPC has not been mapped yet"
        )
