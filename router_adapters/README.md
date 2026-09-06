# Router adapters

The orchestrator depends only on `RouterAdapter`: `detect`, `authenticate`,
`get_status`, `disable_wifi`, `disable_dhcp` and `verify`. Authentication is
stateful by design, so an adapter can retain cookies, rotating tokens, RSA/AES
material or the page context required by a particular firmware.

`FeatureState.UNKNOWN` and `AdapterCapabilities` distinguish unavailable state
from a disabled service. Unsupported operations fail explicitly with
`AdapterUnsupportedOperation`; they never report a false success.

`GLInetAdapter` is the first migrated example. It preserves the current
challenge/login algorithm and the `wifi.set_config` operation on `wifi2g`.
Its firmware-specific DHCP RPC is deliberately marked unsupported until that
protocol has been captured and tested. The existing switcher remains untouched.

`AdapterRegistry` provides deterministic local discovery. It only probes types
registered by the application and contains no dynamic code generation.
`create_default_registry()` registers the local integrations without performing
network I/O. Normal discovery considers only adapters marked `approved`;
`experimental` adapters require an explicit opt-in and `disabled` adapters are
never probed. `detect_with_report()` preserves the result and error of every
probe for the portal and future discovery service, while `detect()` keeps the
original adapter-or-`None` API.
It also loads generated adapters from `/etc/tfg-ai/approved/manifest.json` and
validated script integrations from `/etc/tfg-ai/integrations/manifest.json`,
only after verifying their stored SHA-256 digests. Generated candidates do not
enter either persistent registry until the corresponding validation and
hardware Wi-Fi shutdown verification succeeds.

All write operations return `OperationResult`. The application-facing
`RouterCoordinator` in `router_integration.py` performs URL validation,
read-only inspection and Wi-Fi shutdown with a mandatory post-write
verification. It is deliberately not connected to the SETUP portal yet.

`MercusysMR1500XAdapter` was generated as a proof of concept through
Codex-assisted discovery against a real router. Its public web resources and
live, non-destructive API responses were used without reusing the repository's
pre-existing manual Mercusys integration. The older switcher remains unchanged
so both approaches can be compared. It remains `experimental` until its Wi-Fi
write path is validated independently on hardware.

`XiaomiR4CMAdapter` was generated in a clean-room Codex experiment against a
real R4CM router. Discovery used only the generic adapter contract and the
HTML, JavaScript and API responses served locally by the device; no pre-existing
manufacturer integration was used. The older Xiaomi script remains unchanged.
