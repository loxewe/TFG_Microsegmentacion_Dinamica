from pathlib import Path


OPENWRT_DIR = Path(__file__).resolve().parents[1] / "openwrt"


def read_service(name):
    return (OPENWRT_DIR / name).read_text(encoding="utf-8")


def test_dhcp_service_uses_procd_and_controller_entrypoint():
    service = read_service("tfg-dhcp")

    assert "USE_PROCD=1" in service
    assert '"$PYTHON" -u "$PROJECT_DIR/controlador_aut.py"' in service
    assert "procd_set_param respawn 3600 5 5" in service
    assert "/var/run/tfg" in service
    assert "/var/log/tfg" in service
    assert 'config_get SETUP_COMPLETE main setup_complete "0"' in service
    assert 'config_get INTERFACE dhcp interface "auto"' in service
    assert 'TFG_INTERFACE="$INTERFACE"' in service


def test_zeek_service_uses_configured_interface_and_log_directory():
    service = read_service("tfg-zeek")

    assert "USE_PROCD=1" in service
    assert '"$ZEEK_BINARY" -i "$INTERFACE"' in service
    assert '"Log::default_logdir=$LOG_DIR"' in service
    assert "procd_set_param respawn 3600 5 5" in service
    assert 'config_get LOG_DIR zeek log_dir "$DEFAULT_LOG_DIR"' in service
    assert "Zeek no está instalado" in service
    assert 'config_get SETUP_COMPLETE main setup_complete "0"' in service
    assert "START=98" in service
    assert 'config_get INTERFACE zeek interface "auto"' in service


def test_discovery_service_is_supervised_and_only_boots_in_normal_mode():
    service = read_service("tfg-discovery")

    assert "USE_PROCD=1" in service
    assert "START=97" in service
    assert 'config_get SETUP_COMPLETE main setup_complete "0"' in service
    assert '"$PYTHON" -u "$PROJECT_DIR/discovery_relay.py"' in service
    assert '--policies "$PROJECT_DIR/policies.json"' in service
    assert '--database "$PROJECT_DIR/database.json"' in service
    assert "procd_set_param respawn 3600 5 5" in service
    assert 'LOG_FILE="$LOG_DIR/discovery.log"' in service
    assert 'config_get INTERFACE discovery interface "auto"' in service


def test_web_service_is_permanent_procd_process():
    service = read_service("tfg-web")

    assert "USE_PROCD=1" in service
    assert "START=95" in service
    assert '"$PYTHON" -u "$PROJECT_DIR/setup_portal.py"' in service
    assert '--listen "$LISTEN" --port "$PORT"' in service
    assert "procd_set_param respawn 3600 5 5" in service
    assert 'config_get ZEEK_LOG_DIR zeek log_dir' in service
    assert "procd_set_param env" in service
    assert 'TFG_ZEEK_LOG_DIR="$ZEEK_LOG_DIR"' in service
    assert 'TFG_INTERFACE="$INTERFACE"' in service
    assert "uhttpd" not in service


def test_ai_discovery_is_an_isolated_on_demand_procd_job():
    service = read_service("tfg-ai-discovery")
    runner = read_service("tfg-ai-discovery-runner")

    assert "USE_PROCD=1" in service
    assert 'boot() {' in service
    assert "no se inicia en el boot" in service
    assert '"$PROJECT_DIR/router_discovery.py"' in service
    assert 'RUNNER="/usr/libexec/tfg-ai-discovery-runner"' in service
    assert 'procd_set_param command "$RUNNER"' in service
    assert 'if [ ! -x "$PYTHON" ]; then' in service
    assert 'config_get CODEX_HOME ai codex_home "$DEFAULT_CODEX_HOME"' in service
    assert 'config_get CREDENTIALS_DIR ai credentials_dir' in service
    assert 'config_get INTEGRATIONS_DIR ai integrations_dir' in service
    assert 'config_get DNS_SERVERS ai dns_servers "$DEFAULT_DNS_SERVERS"' in service
    assert 'if [ ! -f "$CODEX_HOME/auth.json" ]; then' in service
    assert 'procd_set_param env HOME="/root" CODEX_HOME="$CODEX_HOME"' in service
    assert '"$STATE_DIR" "$JOB_ID"' in service
    assert '"$DNS_SERVERS" "$INTEGRATIONS_DIR"' in service
    assert '--state-dir "$STATE_DIR"' in runner
    assert '--integrations-dir "$INTEGRATIONS_DIR" run "$JOB_ID"' in runner
    assert '--codex-binary "$CODEX_BINARY"' in runner
    assert '--credentials-dir "$CREDENTIALS_DIR"' in runner
    assert 'DNS_SERVERS="$9"' in runner
    assert 'INTEGRATIONS_DIR="${10}"' in runner
    assert 'rm -f "$CREDENTIALS_DIR/$JOB_ID.json"' in runner
    assert "danger-full-access" not in service


def test_ai_runner_changes_only_host_resolver_and_always_restores_it():
    runner = read_service("tfg-ai-discovery-runner")

    assert 'HOST_RESOLV="/tmp/resolv.conf"' in runner
    assert 'UPSTREAM_RESOLV="/tmp/resolv.conf.d/resolv.conf.auto"' in runner
    assert 'trap cleanup EXIT INT TERM' in runner
    assert 'cp "$HOST_RESOLV" "$BACKUP_FILE"' in runner
    assert 'cat "$UPSTREAM_RESOLV" >> "$DISCOVERY_RESOLV"' in runner
    assert 'cp "$DISCOVERY_RESOLV" "$HOST_RESOLV"' in runner
    assert "for dns_server in $DNS_SERVERS; do" in runner
    assert 'cp "$BACKUP_FILE" "$HOST_RESOLV"' in runner
    assert 'if [ "$1" = "--restore-only" ]; then' in runner
    assert "uci" not in runner
    assert "/etc/init.d/dnsmasq" not in runner


def test_web_recovers_stale_local_resolver_before_starting():
    service = read_service("tfg-web")

    assert 'AI_DNS_RUNNER="/usr/libexec/tfg-ai-discovery-runner"' in service
    assert '"$AI_DNS_RUNNER" --restore-only' in service


def test_web_initializes_ai_registries_in_persistent_storage():
    service = read_service("tfg-web")

    assert 'AI_INTEGRATIONS_DIR="/etc/tfg-ai/integrations"' in service
    assert 'LEGACY_AI_INTEGRATIONS_DIR="/var/lib/tfg-ai/integrations"' in service
    assert (
        'BUNDLED_AI_INTEGRATIONS_RELATIVE_DIR='
        '"docs/experiments/generated_integrations"' in service
    )
    assert 'AI_APPROVED_DIR="/etc/tfg-ai/approved"' in service
    assert 'LEGACY_AI_APPROVED_DIR="/var/lib/tfg-ai/approved"' in service
    assert "initialize_persistent_registries()" in service
    assert '"$PROJECT_DIR/$BUNDLED_AI_INTEGRATIONS_RELATIVE_DIR"' in service
    assert 'cp "$source_dir/manifest.json" "$persistent_dir/manifest.json"' in service


def test_legacy_orchestrator_was_removed():
    assert not (OPENWRT_DIR / "tfg").exists()


def test_uci_config_defines_lifecycle_and_web_service():
    config = read_service("tfg.config")

    assert "config main 'main'" in config
    assert "option setup_complete '0'" in config
    assert "option wifi_radio 'radio0'" in config
    assert "option wifi_section 'wifinet1'" in config
    assert "config service 'web'" in config
    assert "option port '80'" in config
    assert "config service 'discovery'" in config
    assert "option reload_interval '2'" in config
    assert "option rate_limit '20'" in config
    assert "option binary '/opt/zeek/bin/zeek'" in config
    assert "option log_dir '/var/log/tfg/zeek'" in config
    assert "config service 'ai'" in config
    assert "option state_dir '/var/lib/tfg-ai'" in config
    assert "option integrations_dir '/etc/tfg-ai/integrations'" in config
    assert "option codex_home '/root/.codex'" in config
    assert "option credentials_dir '/tmp/tfg-ai-credentials'" in config
    assert "option dns_servers '1.1.1.1 8.8.8.8'" in config
    assert "option discovery_mode 'assisted'" in config


def test_ap_interface_resolver_uses_stable_radio_configuration():
    resolver = read_service("tfg-resolve-ap-interface")

    assert 'config_get WIFI_RADIO main wifi_radio "radio0"' in resolver
    assert 'config_get WIFI_SECTION main wifi_section "wifinet1"' in resolver
    assert 'ubus call network.wireless status' in resolver
    assert "interfaces[@.section='${WIFI_SECTION}'].ifname" in resolver
    assert "interfaces[0].ifname" not in resolver
    assert 'jsonfilter -e "@.${WIFI_RADIO}.up"' in resolver
    assert "jsonfilter -l 2" in resolver
    assert '[ "$#" -eq 1 ] || exit 1' in resolver
    assert '/sys/class/net/$INTERFACE' in resolver


def test_runner_writes_private_pid_and_log_paths():
    runner = read_service("tfg-service-runner")

    assert "umask 077" in runner
    assert 'printf \'%s\\n\' "$$" > "$PID_FILE"' in runner
    assert 'exec "$@" >> "$LOG_FILE" 2>&1' in runner


def test_diagnostics_is_read_only_and_checks_both_runtime_modes():
    diagnostics = read_service("tfg-diagnostics")

    assert diagnostics.startswith("#!/bin/sh")
    assert "Diagnóstico TFG (solo lectura)" in diagnostics
    assert "tfg.main.setup_complete" in diagnostics
    assert 'check_running_service "tfg-web"' in diagnostics
    assert 'check_running_service "tfg-dhcp"' in diagnostics
    assert 'check_running_service "tfg-discovery"' in diagnostics
    assert 'check_stopped_service "tfg-discovery"' in diagnostics
    assert 'check_stopped_service "tfg-dhcp"' in diagnostics
    assert "nft list table netdev tfg_l2" in diagnostics
    assert "nft list table inet tfg_l3" in diagnostics
    assert "nft list set netdev tfg_l2 mdns_allowed_macs" in diagnostics
    assert "nft list set netdev tfg_l2 ssdp_allowed_macs" in diagnostics
    assert "nft list set netdev tfg_l2 broadcast_allowed_macs" in diagnostics
    assert "conn.log" in diagnostics
    assert "dns.log" in diagnostics
    assert "discovery.log" in diagnostics
    assert 'tfg.main.wifi_section' in diagnostics
    assert 'wireless."$WIFI_SECTION".isolate' in diagnostics
    assert 'wireless."$WIFI_SECTION".bridge_isolate' in diagnostics
    assert "tfg-resolve-ap-interface" in diagnostics
    assert "brcmfmac no garantiza" in diagnostics
    assert "http://127.0.0.1/api/status" in diagnostics
    assert "http://127.0.0.1/setup/status" in diagnostics
    assert "MAX_WAIT_ATTEMPTS=10" in diagnostics
    assert 'check_http() {' in diagnostics
    assert "sleep 1" in diagnostics
    assert "uci set" not in diagnostics
    assert "/etc/init.d/tfg-web restart" not in diagnostics
    assert "/etc/init.d/tfg-dhcp start" not in diagnostics
