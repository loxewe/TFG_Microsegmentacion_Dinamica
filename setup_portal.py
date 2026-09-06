import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)

from device_metadata import (
    load_device_aliases,
    remove_device_aliases,
    update_device_alias,
)
from policy_manager import (
    actualizar_politica,
    configurar_interfaz_ap,
    olvidar_politicas_dispositivos,
    obtener_politica,
    restaurar_politica_por_defecto,
)
from policy_observer import load_policy_application
from router_discovery import (
    create_job,
    discard_job_credentials,
    read_job,
    update_job,
)
from router_adapters import (
    AdapterError,
    AdapterUnsupportedOperation,
    Credentials,
)
from router_integration import (
    RouterCoordinator,
    discover_upstream_router,
    normalize_router_url,
)
from zeek_activity import format_byte_count, load_device_activity


PROJECT_DIR = Path(__file__).resolve().parent
DATABASE_PATH = PROJECT_DIR / "database.json"
DEVICE_METADATA_PATH = Path(
    os.environ.get("TFG_DEVICE_METADATA_PATH", "/etc/tfg/device_aliases.json")
)
CAPTIVE_DNS_REDIRECT = "dhcp.@dnsmasq[0].address=/#/192.168.2.1"
SETUP_COMPLETE_OPTION = "tfg.main.setup_complete"
SERVICE_NAMES = ("tfg-dhcp", "tfg-discovery", "tfg-zeek")
NFT_TABLES = (("netdev", "tfg_l2"), ("inet", "tfg_l3"))
AI_STATE_DIR = Path(os.environ.get("TFG_AI_STATE_DIR", "/var/lib/tfg-ai"))
AI_CREDENTIALS_DIR = Path(
    os.environ.get("TFG_AI_CREDENTIALS_DIR", "/tmp/tfg-ai-credentials")
)
ZEEK_LOG_DIR = Path(
    os.environ.get("TFG_ZEEK_LOG_DIR", "/var/log/tfg/zeek")
)
POLICY_LABELS = {
    "internet": "Internet",
    "inter_device": "Interdispositivo",
    "mdns": "mDNS",
    "ssdp": "SSDP",
    "discovery": "multicast de descubrimiento",
    "broadcast": "Broadcast",
}
POLICY_STATUS_LABELS = {
    "applied": "Aplicada",
    "different": "Pendiente de sincronizar",
    "unavailable": "No disponible",
    "inactive": "Bloqueo aplicado",
}
SOURCE_STATUS_LABELS = {
    "available": "fuente disponible",
    "partial": "datos parciales",
    "unavailable": "fuente no verificable",
}
DISCOVERY_PROTOCOLS = (
    ("mdns", "mDNS", "mdns_events"),
    ("ssdp", "SSDP", "ssdp_events"),
    ("broadcast", "broadcast", "broadcast_events"),
)
MAC_IN_TEXT_PATTERN = re.compile(
    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
)
INTERFACE_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,14}$")

ADAPTER_SELECTIONS = {
    "auto": (None, False),
    "glinet": ("glinet", False),
    "xiaomi": ("xiaomi-r4cm", False),
    "mercusys_adapter": ("mercusys-mr1500x", True),
}

ROUTER_SCRIPTS = {
    "mercusys": "Mercusys_TPLink/conmutar_mercusys.py",
    "zte_h298a": "ZTE_H298A_MasMovil/conmutar_zte_requests.py",
    "zte_legacy": "ZTE_Legacy_Digi/conmutar_zte_legacy.py",
}

SETUP_STATE_LOCK = threading.Lock()
SETUP_STATE = {
    "status": "idle",
    "step": "Esperando configuración.",
    "error": None,
}

app = Flask(__name__)


STYLE = """
:root { color-scheme: light; --ink: #172b3a; --muted: #657785;
        --primary: #176b87; --primary-dark: #10536a; --line: #dce5ea; }
body { font-family: Inter, 'Segoe UI', system-ui, sans-serif;
       background: linear-gradient(160deg, #eef5f6 0%, #f7f9fa 48%, #edf1f5 100%);
       color: var(--ink); margin: 0; min-height: 100vh; }
.page { width: min(1180px, calc(100% - 32px)); margin: 28px auto 48px; }
.card { background: white; padding: 28px; border-radius: 12px;
        border: 1px solid rgba(205, 220, 227, .85);
        box-shadow: 0 10px 28px rgba(31, 67, 82, .07); margin-bottom: 22px; }
.setup-card { max-width: 430px; margin: 8vh auto; text-align: center; }
.setup-card .brand-mark { margin: 0 auto 14px; }
.setup-card .mode-badge { margin-bottom: 18px; }
h1, h2, h3 { margin-top: 0; color: var(--ink); }
h1 { letter-spacing: -.025em; }
h2 { font-size: 19px; }
.muted { color: var(--muted); line-height: 1.5; }
.topbar { display: flex; justify-content: space-between; align-items: center;
          gap: 18px; margin-bottom: 24px; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark { display: grid; place-items: center; width: 42px; height: 42px;
              border-radius: 12px; background: var(--primary); color: white;
              font-weight: 800; box-shadow: 0 8px 18px rgba(23,107,135,.2); }
.brand h1 { font-size: 22px; margin: 0; }
.brand p { margin: 2px 0 0; font-size: 13px; }
.toolbar { display: flex; align-items: center; justify-content: flex-end;
           flex-wrap: wrap; gap: 10px; }
.mode-badge { background: #dff3e5; color: #19733a; padding: 6px 11px;
              border-radius: 999px; font-size: 12px; font-weight: 700;
              letter-spacing: .04em; }
.button-link { display: inline-block; background: var(--primary); color: white;
               border-radius: 7px; padding: 9px 13px; text-decoration: none;
               font-size: 13px; font-weight: 650; }
.button-link.secondary { background: #e7eff2; color: #315464; }
.button-link:hover { background: var(--primary-dark); }
select, input, button { width: 100%; padding: 12px; margin: 7px 0;
                        border: 1px solid #c8d1da; border-radius: 6px;
                        box-sizing: border-box; font-size: 15px; }
button { background: var(--primary); color: white; border: 0; cursor: pointer;
         font-weight: 600; }
button:hover { background: var(--primary-dark); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; border-bottom: 1px solid #e5e9ed;
         padding: 11px 8px; vertical-align: middle; }
th { color: #526773; font-size: 12px; letter-spacing: .025em;
     text-transform: uppercase; }
.status { display: inline-block; padding: 3px 9px; border-radius: 999px;
          font-size: 13px; font-weight: 600; }
.on { background: #dff3e5; color: #19733a; }
.off { background: #f9e0e0; color: #a22b2b; }
.notice { padding: 12px; border-radius: 6px; margin-bottom: 18px; }
.success { background: #e1f3e6; color: #196b36; }
.error { background: #fde5e5; color: #932828; }
.policy-form .policy-help { margin: 0 0 12px; text-align: left; }
.policy-groups { display: grid;
                 grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                 gap: 12px; }
.policy-group { min-width: 0; margin: 0; padding: 12px;
                border: 1px solid var(--line); border-radius: 9px; }
.policy-group legend { padding: 0 6px; color: var(--ink); font-size: 13px;
                       font-weight: 750; }
.policy-controls { display: grid; gap: 8px; }
.policy-controls.connectivity { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.policy-controls.discovery { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.policy-toggle { display: flex; flex-direction: column; align-items: center;
                 justify-content: center; gap: 4px; min-width: 0;
                 padding: 8px 4px; text-align: center;
                 border: 1px solid var(--line); border-radius: 7px;
                 background: #f8fafb; cursor: pointer; }
.policy-toggle:focus-within { outline: 3px solid rgba(23,107,135,.18);
                              outline-offset: 1px; }
.policy-toggle input[type=checkbox] { flex: 0 0 auto; width: 18px; height: 18px;
                                      margin: 0; accent-color: var(--primary); }
.policy-toggle-copy { min-width: 0; }
.policy-toggle-name { display: block; color: var(--ink); font-size: 12px;
                      font-weight: 700; white-space: nowrap; }
.policy-toggle-state { display: block; margin-top: 2px; color: var(--muted);
                       font-size: 10px; font-weight: 650; }
.policy-toggle-state::before { content: "Bloqueado"; }
.policy-toggle input:checked + .policy-toggle-copy .policy-toggle-state::before {
  content: "Permitido";
}
.policy-actions { display: flex; justify-content: flex-end; margin-top: 12px;
                  padding-top: 12px; border-top: 1px solid var(--line); }
.policy-actions button { width: auto; margin: 0; padding: 9px 14px; }
.policy-table-form { margin: 0; }
.policy-table th:nth-child(2), .policy-table td:nth-child(2) {
  text-align: center;
}
.policy-table-toggle { display: inline-flex; flex-direction: column;
                       align-items: center; gap: 4px; min-width: 118px;
                       cursor: pointer; }
.policy-table-toggle:focus-within { outline: 3px solid rgba(23,107,135,.18);
                                  outline-offset: 3px; border-radius: 5px; }
.policy-table-toggle input[type=checkbox] { flex: 0 0 auto; width: 18px;
                                            height: 18px; margin: 0;
                                            accent-color: var(--primary); }
.policy-table-state { color: var(--muted); font-size: 12px;
                      font-weight: 650; white-space: nowrap; }
.policy-table-state::before { content: "Bloqueado"; }
.policy-table-toggle input:checked + .policy-table-state::before {
  content: "Permitido";
}
.activity { min-width: 220px; }
.activity-meta { display: block; margin-top: 5px; font-size: 12px;
                 color: #6d7b88; line-height: 1.45; }
.activity-items { margin-top: 6px; font-size: 12px; color: #425566;
                  overflow-wrap: anywhere; }
.warn { background: #fff0cc; color: #855d00; }
.neutral { background: #e8edf2; color: #536270; }
.policy-state { margin-bottom: 9px; }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 12px; }
.summary-grid + .notice { margin-top: 18px; }
.summary-item { background: #f4f8f9; border: 1px solid #e2ecef;
                border-radius: 9px; padding: 16px; color: var(--muted); }
.summary-number { display: block; color: #203040; font-size: 26px;
                  font-weight: 700; }
.warning { background: #fff0cc; color: #855d00; }
.danger-button { background: #a83b3b; }
.danger-button:hover { background: #842d2d; }
.cleanup-form { display: flex; align-items: center; gap: 12px;
                margin: 16px 0 18px; }
.cleanup-form button { width: auto; margin: 0; }
.cleanup-form p { margin: 0; }
.protocol-grid { display: grid;
                 grid-template-columns: repeat(3, minmax(0, 1fr));
                 gap: 12px; }
.protocol-card { border: 1px solid var(--line); border-radius: 9px;
                 padding: 15px; background: #f8fafb; }
.protocol-card h3 { margin-bottom: 8px; font-size: 16px; }
.protocol-card p { margin: 8px 0 0; font-size: 13px; line-height: 1.45; }
.protocol-alert { margin-top: 7px; padding: 8px 10px; border-radius: 7px;
                  background: #fff6df; color: #715000; font-size: 12px;
                  line-height: 1.4; }
.trust-box { display: grid; grid-template-columns: 1fr auto;
             align-items: center; gap: 16px; margin-top: 18px;
             padding-top: 16px; border-top: 1px solid var(--line); }
.trust-box form { margin: 0; }
.trust-box button { width: auto; margin: 0; }
.legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px;
          color: var(--muted); font-size: 12px; }
.policy-editor { margin-top: 10px; }
.policy-editor summary, .technical summary { color: var(--primary);
                  cursor: pointer; font-weight: 650; }
.policy-editor[open] summary { margin-bottom: 10px; }
.technical { margin-top: 12px; color: var(--muted); font-size: 12px;
             overflow-wrap: anywhere; }
.empty-state { padding: 26px; border: 1px dashed #cbd9df; border-radius: 9px;
               text-align: center; color: var(--muted); background: #f8fafb; }
.device-link { color: #2377b9; font-weight: 600; text-decoration: none; }
.device-link:hover { text-decoration: underline; }
.back-link { display: inline-block; margin-bottom: 18px; color: #2377b9; }
.detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
               gap: 22px; }
.eyebrow { margin: 0 0 6px; color: #5d7480; font-size: 11px;
           font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.topbar { background: #102f3f; color: white; padding: 22px 24px;
          border-radius: 14px; box-shadow: 0 14px 32px rgba(16,47,63,.18); }
.topbar h1, .topbar .muted { color: white; }
.topbar .muted { opacity: .76; }
.topbar .brand-mark { background: #42a6a1; box-shadow: none; }
.service-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
                gap: 14px; }
.service-card { border: 1px solid var(--line); border-radius: 11px;
                padding: 17px; background: #f8fbfc; }
.service-card strong { display: block; margin-bottom: 9px; font-size: 15px; }
.summary-grid { grid-template-columns: repeat(5, minmax(0, 1fr)); }
.summary-item.alert-summary { background: #fff8e8; border-color: #f0d99d; }
.summary-item.alert-summary .summary-number { color: #9a6500; }
.section-heading { display: flex; justify-content: space-between;
                   align-items: flex-start; gap: 20px; margin-bottom: 18px; }
.section-heading h2 { margin-bottom: 5px; }
.section-heading p { margin: 0; max-width: 700px; }
.device-group + .device-group { margin-top: 22px; }
.device-group h3 { margin-bottom: 10px; padding: 10px 12px;
                   border-radius: 7px; background: #f4f7f9;
                   color: #425566; font-size: 12px; letter-spacing: .025em;
                   text-transform: uppercase; }
.device-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
               gap: 14px; }
.device-card { min-width: 0; background: #fbfcfd; border: 1px solid var(--line);
               border-radius: 11px; overflow: hidden; }
.device-card:last-child:nth-child(odd) { grid-column: 1 / -1;
                                        width: calc((100% - 14px) / 2);
                                        justify-self: center; }
.device-card-header { display: grid;
                      grid-template-columns: minmax(0, 1.4fr) minmax(120px, .6fr);
                      gap: 12px; padding: 16px 12px; }
.device-card-section { border-top: 1px solid var(--line); padding: 16px 12px; }
.device-card-label { display: block; color: var(--muted); font-size: 10px;
                     font-weight: 800; letter-spacing: .05em;
                     text-transform: uppercase; margin-bottom: 7px; }
.device-name { display: block; font-size: 15px; margin-bottom: 5px; }
.device-address { font-size: 12px; line-height: 1.55; }
.protocol-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 9px; }
.protocol-chip { display: inline-flex; align-items: center; gap: 5px;
                 padding: 4px 8px; border-radius: 999px; background: #e9eef1;
                 color: #546873; font-size: 11px; font-weight: 700; }
.protocol-chip.observed { background: #fff0cc; color: #805a00; }
.protocol-chip.allowed { background: #dff3e5; color: #19733a; }
.action-row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.action-row form { margin: 0; }
.action-row button { width: auto; margin: 0; padding: 9px 12px; }
.policy-editor { border-top: 1px solid var(--line); padding-top: 10px; }
.policy-editor .policy-form { background: white; border: 1px solid var(--line);
                              border-radius: 9px; padding: 12px; }
.technical-panel { margin-top: 14px; border: 1px solid var(--line);
                   border-radius: 9px; background: #f8fafb; padding: 0 14px; }
.technical-panel summary { padding: 13px 0; color: var(--primary);
                           cursor: pointer; font-weight: 700; }
.technical-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
                  gap: 10px; padding: 0 0 14px; }
.technical-item { background: white; border: 1px solid var(--line);
                  border-radius: 7px; padding: 10px; overflow-wrap: anywhere; }
.technical-item span { display: block; color: var(--muted); font-size: 11px;
                       text-transform: uppercase; letter-spacing: .04em; }
.technical-item strong { display: block; margin-top: 4px; font-size: 13px; }
.setup-layout { display: grid;
                grid-template-columns: minmax(260px,.8fr) minmax(420px,1.2fr);
                max-width: 940px; margin: 5vh auto; border-radius: 16px;
                overflow: hidden; box-shadow: 0 18px 44px rgba(31,67,82,.14); }
.setup-intro { background: #102f3f; color: white; padding: 42px 34px; }
.setup-intro h1, .setup-intro .muted { color: white; }
.setup-intro .muted { opacity: .76; }
.setup-intro .brand-mark { background: #42a6a1; box-shadow: none; margin-bottom: 28px; }
.setup-steps { list-style: none; padding: 0; margin: 30px 0 0;
               counter-reset: setup; }
.setup-steps li { position: relative; padding: 0 0 23px 42px; line-height: 1.45; }
.setup-steps li::before { counter-increment: setup; content: counter(setup);
                          position: absolute; left: 0; top: -3px; display: grid;
                          place-items: center; width: 27px; height: 27px;
                          border-radius: 50%; background: rgba(255,255,255,.13);
                          color: #9fe1dd; font-size: 12px; font-weight: 800; }
.setup-panel { margin: 0; border: 0; border-radius: 0; box-shadow: none;
               padding: 38px; text-align: left; }
.setup-panel .mode-badge { display: inline-block; margin-bottom: 16px; }
.form-section { margin-top: 22px; padding-top: 20px; border-top: 1px solid var(--line); }
.form-section h2 { margin-bottom: 6px; }
.field { display: block; margin-top: 13px; color: #425966;
         font-size: 13px; font-weight: 700; }
.field input, .field select { margin-top: 6px; background: #fbfcfd; }
input:focus, select:focus { outline: 3px solid rgba(23,107,135,.13);
                            border-color: var(--primary); }
.form-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
                margin-top: 18px; }
.secondary-button { background: #e7eff2; color: #315464; }
.secondary-button:hover { background: #d6e4e9; }
.setup-note { border-left: 3px solid #42a6a1; background: #eef8f7;
              padding: 11px 13px; border-radius: 0 7px 7px 0;
              color: #405b65; font-size: 13px; line-height: 1.45; }
.progress-orb { width: 48px; height: 48px; border: 5px solid #dbe8eb;
                border-top-color: var(--primary); border-radius: 50%;
                margin: 8px auto 22px; animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
/* Tema oscuro local: no necesita recursos externos ni JavaScript. */
:root { color-scheme: dark; --ink: #edf5f7; --muted: #9cb0ba;
        --primary: #4fc3bd; --primary-dark: #38a7a2; --line: #29414d; }
body { background: #05090c; color: var(--ink); }
.card { background: #0d1820; border-color: #203642;
        box-shadow: 0 12px 32px rgba(0,0,0,.28); }
.topbar, .setup-intro { background: #07141b; }
h1, h2, h3 { color: var(--ink); }
.eyebrow { color: #75cfc9; }
.button-link.secondary, .secondary-button { background: #1b303b; color: #d8e9ed; }
.button-link.secondary:hover, .secondary-button:hover { background: #284653; }
select, input { background: #0a141a; color: var(--ink); border-color: #38505c; }
.field { color: #c2d2d8; }
.field input, .field select { background: #091319; }
th, td { border-color: #263b45; }
th { color: #9fb3bc; }
.service-card, .summary-item, .protocol-card, .empty-state {
  background: #101f27; border-color: #29414d;
}
.summary-item.alert-summary { background: #2a2211; border-color: #634d1d; }
.summary-item.alert-summary .summary-number { color: #f0c968; }
.summary-number { color: #edf5f7; }
.device-card { background: #0f1c23; border-color: #29414d; }
.device-card-section { border-color: #29414d; }
.device-group h3 { background: #14252e; color: #c4d6dc; }
.policy-editor .policy-form, .technical-item { background: #091319; border-color: #29414d; }
.policy-group, .policy-toggle { border-color: #29414d; }
.policy-toggle { background: #101f27; }
.technical-panel { background: #101f27; border-color: #29414d; }
.neutral { background: #263944; color: #c2d2d8; }
.on { background: #123c2a; color: #79e2a5; }
.off { background: #482020; color: #ff9a9a; }
.warn, .warning { background: #403112; color: #f4cf72; }
.success { background: #123c2a; color: #8be4ae; }
.error { background: #482020; color: #ffaaaa; }
.protocol-alert { background: #352a13; color: #f2cf7a; }
.protocol-chip { background: #263944; color: #c6d6dc; }
.protocol-chip.observed { background: #403112; color: #f4cf72; }
.protocol-chip.allowed { background: #123c2a; color: #79e2a5; }
.setup-note { background: #102b2b; color: #b8d9d6; }
@media (max-width: 800px) {
  .detail-grid { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: repeat(2, 1fr); }
  .service-grid { grid-template-columns: 1fr; }
  .setup-layout { grid-template-columns: 1fr; margin: 18px auto; }
  .setup-intro { padding: 28px 24px; }
  .setup-steps { display: none; }
  .setup-panel { padding: 26px 20px; }
  .form-actions { grid-template-columns: 1fr; }
  .technical-grid { grid-template-columns: 1fr; }
  .topbar { align-items: flex-start; flex-direction: column; }
  .toolbar { justify-content: flex-start; }
  .protocol-grid { grid-template-columns: 1fr; }
  .trust-box { grid-template-columns: 1fr; }
  .cleanup-form { align-items: stretch; flex-direction: column; }
  .cleanup-form button, .trust-box button { width: 100%; }
  table, thead, tbody, th, td, tr { display: block; }
  thead { display: none; }
  tr { border-bottom: 1px solid #dfe5ea; padding: 10px 0; }
  td { border: 0; }
  .policy-table td:not(.policy-table-name) { display: grid;
    grid-template-columns: minmax(96px, 42%) minmax(0, 1fr); gap: 8px;
    align-items: center; padding: 6px 8px; }
  .policy-table td:not(.policy-table-name)::before { content: attr(data-label);
    color: var(--muted); font-size: 11px; font-weight: 700;
    letter-spacing: .025em; text-transform: uppercase; }
  .policy-table-name { color: var(--ink); font-weight: 750;
                       padding-bottom: 6px; }
  .device-grid { grid-template-columns: 1fr; }
  .device-card:last-child:nth-child(odd) { grid-column: auto; width: auto;
                                          justify-self: stretch; }
  .device-card-header { grid-template-columns: 1fr; }
}
"""


SETUP_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Configuración TFG</title>
  <style>{{ style }}</style>
</head>
<body>
  <div class="page">
    <div class="setup-layout">
      <aside class="setup-intro">
        <div class="brand-mark">TFG</div>
        <p class="eyebrow">Controlador de microsegmentación</p>
        <h1>Migra tu red sin perder el control</h1>
        <p class="muted">Un asistente local prepara la Raspberry, verifica el router y activa la protección de cada dispositivo.</p>
        <ol class="setup-steps">
          <li>Detectar y comprobar el router doméstico.</li>
          <li>Conservar el nombre y la contraseña de la red.</li>
          <li>Activar DHCP, Zeek y microsegmentación.</li>
        </ol>
      </aside>
      <main class="card setup-panel">
      <span class="mode-badge">CONFIGURACIÓN INICIAL</span>
      <h1>Configuración inicial</h1>
      <p class="muted">Introduce los datos de la red. La comprobación inicial no modifica el router.</p>
      <div id="router-inspection-result" aria-live="polite">
      {% if error %}<div class="notice error">{{ error }}</div>{% endif %}
      {% if inspection %}
      <div class="notice success">
        Router detectado: {{ inspection.adapter_id }}.
        Wi-Fi: {{ inspection.status.wifi.value }}{% if inspection.status.dhcp is defined and inspection.status.dhcp.value is defined and inspection.status.dhcp.value != 'unknown' %};
        DHCP: {{ inspection.status.dhcp.value }}{% endif %}.
      </div>
      {% endif %}
      </div>
      {% if unknown_router_url %}
      <section class="form-section">
        <p class="eyebrow">Integración asistida</p>
        <h2>Router todavía no compatible</h2>
        <p class="setup-note">Codex trabajará en un espacio aislado y la contraseña se eliminará al terminar.</p>
      <form method="post" action="{{ url_for('start_router_discovery') }}" autocomplete="off">
        <input type="hidden" name="router_url" value="{{ unknown_router_url }}">
        <input type="text" name="username" value="{{ values.username }}"
               placeholder="Usuario de administración (opcional)">
        <input type="password" name="password"
               placeholder="Contraseña para la exploración" required>
        <input type="text" name="ssid" maxlength="32"
               value="{{ values.ssid }}" placeholder="Nombre de la Wi-Fi original" required>
        <input type="password" name="wifi_password" minlength="8" maxlength="63"
               placeholder="Contraseña de la Wi-Fi original" required>
        <select name="mode">
          <option value="assisted">Asistido con integraciones existentes (recomendado)</option>
          <option value="clean_room">Evaluación clean-room</option>
        </select>
        <p class="muted">
          Codex investigará el router, creará una integración, desactivará su
          Wi-Fi y comprobará el resultado. No modificará el DHCP. La contraseña
          se elimina al terminar.
        </p>
        <button type="submit">Integrar este router con Codex</button>
      </form>
      </section>
      {% endif %}
      <section class="form-section">
      <p class="eyebrow">Datos de migración</p>
      <h2>Router y nueva red</h2>
      <form id="setup-form" method="post" action="{{ url_for('setup') }}" autocomplete="off">
        <label class="field">Modelo o familia del router
        <select name="router_brand" required>
          <option value="auto" {% if values.router_brand == 'auto' %}selected{% endif %}>Detectar automáticamente</option>
          <option value="glinet" {% if values.router_brand == 'glinet' %}selected{% endif %}>GL.iNet (adaptador)</option>
          <option value="xiaomi" {% if values.router_brand == 'xiaomi' %}selected{% endif %}>Xiaomi R4CM (adaptador)</option>
          <option value="mercusys_adapter" {% if values.router_brand == 'mercusys_adapter' %}selected{% endif %}>Mercusys MR1500X (adaptador experimental)</option>
          <option value="mercusys" {% if values.router_brand == 'mercusys' %}selected{% endif %}>Mercusys / TP-Link (compatibilidad legacy)</option>
          <option value="zte_h298a" {% if values.router_brand == 'zte_h298a' %}selected{% endif %}>ZTE H298A (legacy)</option>
          <option value="zte_legacy" {% if values.router_brand == 'zte_legacy' %}selected{% endif %}>ZTE Legacy</option>
        </select>
        </label>
        <label class="field">Dirección del router
        <input type="url" name="router_url"
               value="{{ values.router_url }}"
               placeholder="http://192.168.1.1" required>
        </label>
        {% if upstream_router %}
        <p class="muted">
          Puerta de enlace detectada automáticamente:
          {{ upstream_router.gateway }} por {{ upstream_router.interface or 'interfaz desconocida' }}.
          Puedes corregirla manualmente si esta red usa otra topología.
        </p>
        {% else %}
        <p class="muted">
          No se encontró una puerta de enlace privada. Introduce manualmente
          la dirección del router doméstico.
        </p>
        {% endif %}
        <label class="field">Usuario de administración
        <input type="text" name="username"
               value="{{ values.username }}"
               placeholder="Usuario de administración (opcional)">
        </label>
        <label class="field">Contraseña de administración
        <input type="password" name="password"
               placeholder="No se mostrará ni se guardará" required autocomplete="current-password">
        </label>
        <label class="field">Nombre de la Wi-Fi
        <input type="text" name="ssid" maxlength="32"
               placeholder="Nombre de la Wi-Fi original" required>
        </label>
        <label class="field">Contraseña de la Wi-Fi
        <input type="password" name="wifi_password" minlength="8" maxlength="63"
               placeholder="Entre 8 y 63 caracteres" required autocomplete="new-password">
        </label>
        <div class="form-actions">
        <button id="inspect-router" type="submit"
                class="secondary-button"
                formaction="{{ url_for('inspect_setup_router') }}">
          Comprobar router sin modificarlo
        </button>
        <button type="submit">Iniciar migración</button>
        </div>
      </form>
      </section>
      </main>
    </div>
  </div>
  <script>
    const setupForm = document.getElementById("setup-form");
    const inspectButton = document.getElementById("inspect-router");
    const inspectionResult = document.getElementById(
      "router-inspection-result"
    );

    inspectButton.addEventListener("click", async (event) => {
      event.preventDefault();
      if (!setupForm.reportValidity()) return;

      inspectButton.disabled = true;
      inspectionResult.innerHTML =
        '<div class="notice">Comprobando el router sin modificarlo...</div>';
      try {
        const response = await fetch(inspectButton.formAction, {
          method: "POST",
          body: new FormData(setupForm),
          headers: {"Accept": "application/json"},
        });
        const result = await response.json();
        if (result.unknown_router) {
          const notice = document.createElement("div");
          notice.className = "notice error";
          notice.textContent = result.error;
          const integrate = document.createElement("button");
          integrate.type = "button";
          integrate.textContent = "Integrar este router con Codex";
          integrate.addEventListener("click", () => {
            setupForm.action = "{{ url_for('start_router_discovery') }}";
            const mode = document.createElement("input");
            mode.type = "hidden";
            mode.name = "mode";
            mode.value = "assisted";
            setupForm.appendChild(mode);
            setupForm.submit();
          });
          inspectionResult.replaceChildren(notice, integrate);
          return;
        }
        const notice = document.createElement("div");
        notice.className = "notice " + (result.ok ? "success" : "error");
        const dhcpSummary = result.dhcp !== undefined &&
          result.dhcp !== "unknown"
          ? `; DHCP: ${result.dhcp}`
          : "";
        notice.textContent = result.ok
          ? `Router detectado: ${result.adapter_id}. ` +
            `Wi-Fi: ${result.wifi}${dhcpSummary}.`
          : result.error;
        inspectionResult.replaceChildren(notice);
      } catch (error) {
        const notice = document.createElement("div");
        notice.className = "notice error";
        notice.textContent =
          "No se pudo completar la comprobación. Inténtalo de nuevo.";
        inspectionResult.replaceChildren(notice);
      } finally {
        inspectButton.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


PROGRESS_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Migración en curso</title>
  <style>{{ style }}</style>
</head>
<body>
  <div class="page">
    <div class="card setup-card">
      <div class="brand-mark">TFG</div>
      <span class="mode-badge">CONFIGURACIÓN INICIAL</span>
      <h1>Migración en curso</h1>
      <div class="progress-orb" aria-hidden="true"></div>
      <p id="step" class="muted">Preparando la configuración...</p>
      <div id="failure" class="notice error" hidden></div>
      <a id="retry" href="{{ url_for('setup') }}" hidden>Volver al formulario</a>
    </div>
  </div>
  <script>
    async function refreshStatus() {
      try {
        const response = await fetch("{{ url_for('setup_status') }}",
                                     {cache: "no-store"});
        const state = await response.json();
        document.getElementById("step").textContent = state.step;
        if (state.status === "success") {
          window.location.replace("{{ url_for('dashboard') }}");
          return;
        }
        if (state.status === "error") {
          const failure = document.getElementById("failure");
          failure.textContent = state.error || "La migración ha fallado.";
          failure.hidden = false;
          document.getElementById("retry").hidden = false;
          return;
        }
      } catch (error) {
        document.getElementById("step").textContent =
          "Esperando que el panel vuelva a estar disponible...";
      }
      window.setTimeout(refreshStatus, 1500);
    }
    refreshStatus();
  </script>
</body>
</html>
"""


DISCOVERY_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Descubrimiento de router</title>
  <style>{{ style }}</style>
</head>
<body>
  <div class="page">
    <div class="card setup-card">
      <div class="brand-mark">TFG</div>
      <span class="mode-badge">DESCUBRIMIENTO ASISTIDO</span>
      <h1>Integración automática del router</h1>
      {% if error %}<div class="notice error">{{ error }}</div>{% endif %}
      <div class="progress-orb" aria-hidden="true"></div>
      <p id="discovery-message" class="muted">Consultando el estado...</p>
      <div id="ready" hidden>
        <div class="notice success">
          <strong>Integración generada y verificada en el router.</strong><br>
          <span id="observation"></span>
        </div>
        <p class="muted">
          La Wi-Fi del router ya está desactivada. Al continuar se configurará
          el punto de acceso de la Raspberry y se iniciará el modo NORMAL.
        </p>
        <form method="post"
              action="{{ url_for('migrate_discovered_router', job_id=job_id) }}">
          <input type="text" name="ssid" maxlength="32"
                 placeholder="Nombre de la nueva Wi-Fi" required>
          <input type="password" name="wifi_password" minlength="8" maxlength="63"
                 placeholder="Contraseña de la nueva Wi-Fi" required autocomplete="new-password">
          <button type="submit">Configurar Raspberry y completar migración</button>
        </form>
      </div>
      <div id="failure" class="notice error" hidden></div>
      <a href="{{ url_for('setup') }}">Volver al SETUP</a>
    </div>
  </div>
  <script>
    async function refreshDiscovery() {
      try {
        const response = await fetch(
          "{{ url_for('router_discovery_status', job_id=job_id) }}",
          {cache: "no-store"}
        );
        const state = await response.json();
        document.getElementById("discovery-message").textContent =
          state.message || state.status;
        if (state.status === "script_ready") {
          const observation = state.observation || {};
          document.getElementById("observation").textContent =
            "Codex confirmó la Wi-Fi desactivada y guardó la integración.";
          document.getElementById("ready").hidden = false;
          return;
        }
        if (state.status === "completing_setup") {
          document.getElementById("discovery-message").textContent =
            "Wi-Fi desactivada. Configurando automáticamente la Raspberry...";
        }
        if (state.status === "completed") {
          window.location.replace("{{ url_for('dashboard') }}");
          return;
        }
        if (state.status === "approved") {
          window.location.replace("{{ url_for('setup') }}");
          return;
        }
        if (["failed", "failed_validation", "failed_readonly_validation",
             "insufficient_evidence", "hardware_test_failed", "setup_failed",
             "rejected"].includes(state.status)) {
          const failure = document.getElementById("failure");
          failure.textContent = state.message || "El descubrimiento ha fallado.";
          failure.hidden = false;
          return;
        }
      } catch (error) {
        document.getElementById("discovery-message").textContent =
          "Esperando al servicio de descubrimiento...";
      }
      window.setTimeout(refreshDiscovery, 2000);
    }
    refreshDiscovery();
  </script>
</body>
</html>
"""


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Panel TFG</title>
  <style>{{ style }}</style>
</head>
<body>
  <div class="page">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">TFG</div>
        <div><h1>Controlador de microsegmentación</h1></div>
      </div>
      <div class="toolbar">
        <span id="dashboard-updated" class="muted">Actualizado: {{ rendered_at }}</span>
        <a class="button-link secondary" href="{{ url_for('dashboard') }}">Actualizar</a>
      </div>
    </header>
    {% if message %}<div class="notice success">{{ message }}</div>{% endif %}
    {% if error %}<div class="notice error">{{ error }}</div>{% endif %}
    <div id="service-status-panel" class="card">
      <h2>Estado general</h2>
      <div class="service-grid">
        <div class="service-card">
          <strong>DHCP</strong>
          <span class="status {{ 'on' if status.dhcp else 'off' }}">{{ 'Activo' if status.dhcp else 'Inactivo' }}</span>
        </div>
        <div class="service-card">
          <strong>Zeek</strong>
          <span class="status {{ 'on' if status.zeek else 'off' }}">{{ 'Activo' if status.zeek else 'Inactivo' }}</span>
        </div>
        <div class="service-card">
          <strong>Relay mDNS/SSDP</strong>
          <span class="status {{ 'on' if status.discovery else 'off' }}">{{ 'Activo' if status.discovery else 'Inactivo' }}</span>
        </div>
        <div class="service-card">
          <strong>Aislamiento Wi-Fi</strong>
          <span class="status {{ 'on' if status.wifi_isolation else 'off' }}">{{ 'Activo' if status.wifi_isolation else 'Inactivo' }}</span>
        </div>
        <div class="service-card">
          <strong>Microsegmentación</strong>
          <span class="status {{ 'on' if status.microsegmentation else 'off' }}">{{ 'Activo' if status.microsegmentation else 'Inactivo' }}</span>
        </div>
      </div>
    </div>
    <div id="device-summary-panel" class="card">
      <h2>Resumen de dispositivos</h2>
      <div class="summary-grid">
        <div class="summary-item"><span class="summary-number">{{ summary.total }}</span>registrados</div>
        <div class="summary-item"><span class="summary-number">{{ summary.active }}</span>activos</div>
        <div class="summary-item"><span class="summary-number">{{ summary.inactive }}</span>inactivos</div>
        <div class="summary-item"><span class="summary-number">{{ summary.recent }}</span>con actividad reciente</div>
        <div class="summary-item alert-summary"><span class="summary-number">{{ summary.needs_authorization }}</span>con alertas</div>
      </div>
      {% if summary.inactive %}
      <form class="cleanup-form" method="post"
            action="{{ url_for('cleanup_inactive') }}"
            onsubmit="return confirm('Se eliminarán únicamente dispositivos inactivos verificados. ¿Continuar?');">
        <button class="danger-button" type="submit">Limpiar dispositivos inactivos</button>
        <p class="muted">Elimina inventario, alias y políticas específicas de
        {{ summary.inactive }} dispositivo(s). El DHCP se reinicia brevemente.</p>
      </form>
      {% endif %}
      {% if summary.needs_authorization %}
      <div class="notice warning">{{ summary.needs_authorization }} {{ 'dispositivo necesita' if summary.needs_authorization == 1 else 'dispositivos necesitan' }} autorización para descubrimiento local.</div>
      {% endif %}
      {% if summary.policy_different %}
      <div class="notice warning">{{ summary.policy_different }} {{ 'dispositivo tiene una política pendiente' if summary.policy_different == 1 else 'dispositivos tienen políticas pendientes' }} en nftables.</div>
      {% endif %}
      {% if summary.policy_unavailable %}
      <div class="notice error">No se puede verificar {{ 'la política de 1 dispositivo activo' if summary.policy_unavailable == 1 else 'las políticas de ' ~ summary.policy_unavailable ~ ' dispositivos activos' }}.</div>
      {% endif %}
      {% if summary.zeek_limited %}
      <div class="notice warning">Actividad Zeek parcial o no verificable en {{ summary.zeek_limited }} {{ 'dispositivo activo' if summary.zeek_limited == 1 else 'dispositivos activos' }}.</div>
      {% endif %}
      {% if summary.active and not summary.policy_different and not summary.policy_unavailable %}
      <div class="notice success">Todas las políticas activas están aplicadas.</div>
      {% endif %}
    </div>
    <div id="device-list-panel" class="card">
      <div class="section-heading">
        <div>
          <h2>Dispositivos y políticas</h2>
        </div>
      </div>
      {% if devices %}
      {% set device_groups = [
        (true, 'Dispositivos activos', summary.active),
        (false, 'Dispositivos inactivos', summary.inactive)
      ] %}
      {% for group_state, group_title, group_count in device_groups %}
        {% set group_devices = devices | selectattr('created', 'equalto', group_state) | list %}
        {% if group_devices %}
        <section class="device-group" data-state="{{ 'active' if group_state else 'inactive' }}">
          <h3>{{ group_title }} ({{ group_count }})</h3>
          <div class="device-grid">
          {% for device in group_devices %}
          <article class="device-card">
            <div class="device-card-header">
              <div>
                <span class="device-card-label">Dispositivo</span>
                <a class="device-link device-name" href="{{ url_for('device_detail', mac=device.mac) }}">{{ device.name }}</a>
                <small class="muted device-address">{{ device.mac }}{% if device.alias and device.hostname %}<br>DHCP: {{ device.hostname }}{% endif %}</small>
              </div>
              <div>
                <span class="device-card-label">Dirección</span>
                <strong>{{ device.ip }}</strong><br>
                <small class="muted">{{ 'Conectado' if device.created else 'Inactivo' }}</small>
              </div>
            </div>
            <div class="device-card-section activity">
              <span class="device-card-label">Actividad Zeek</span>
              {% if device.activity.last_seen %}
                <span class="status {{ 'on' if device.activity.recent else 'off' }}">
                  {{ 'reciente' if device.activity.recent else 'sin actividad reciente' }}
                </span>
                <span class="activity-meta">
                  Muestra: {{ device.activity.connections }} conexiones ·
                  ↑ {{ format_bytes(device.activity.bytes_sent) }} ·
                  ↓ {{ format_bytes(device.activity.bytes_received) }}
                </span>
                <div class="activity-items">
                  Internet {{ device.activity.external_attempts }} ·
                  Interdispositivo {{ device.activity.peer_flows }} ·
                  descubrimiento {{ device.activity.mdns_events + device.activity.ssdp_events }}
                </div>
                {% set observed_protocols = device.observations|default([])|selectattr('observed')|list %}
                {% if observed_protocols %}
                <div class="protocol-chips" aria-label="Protocolos detectados">
                {% for observation in observed_protocols %}
                  <span class="protocol-chip {{ 'allowed' if observation.applied else 'observed' }}">
                    {% if observation.id == 'mdns' %}mDNS / Bonjour{% elif observation.id == 'ssdp' %}SSDP / UPnP{% else %}Broadcast{% endif %}
                    · {{ observation.events }}
                  </span>
                {% endfor %}
                </div>
                {% endif %}
                {% set unauthorized_protocols = device.observations|default([])|selectattr('needs_authorization')|list %}
                {% if unauthorized_protocols %}
                <div class="protocol-alert">Este dispositivo necesita autorización para descubrimiento local: {% for observation in unauthorized_protocols %}{% if not loop.first %}{{ ', ' if not loop.last else ' y ' }}{% endif %}{{ observation.label }}{% endfor %}.</div>
                {% endif %}
              {% else %}
                {% if device.activity.source_status == 'unavailable' %}
                  <span class="status off">Zeek no verificable</span>
                {% elif device.activity.source_status == 'partial' %}
                  <span class="status warn">Datos Zeek parciales</span>
                {% else %}
                  <span class="muted">Sin actividad observada</span>
                {% endif %}
              {% endif %}
            </div>
            <div class="device-card-section">
              <span class="device-card-label">Políticas</span>
              <div class="policy-state">
                {% if device.enforcement.status == 'applied' %}
                  <span class="status on">aplicada en nftables</span>
                {% elif device.enforcement.status == 'different' %}
                  <span class="status warn">pendiente o diferente</span>
                {% elif device.enforcement.status == 'inactive' %}
                  <span class="status neutral">dispositivo inactivo</span>
                {% else %}
                  <span class="status off">no verificable</span>
                {% endif %}
                {% if device.enforcement.differences %}
                <span class="activity-meta">
                  Revisar:
                  {% for name in device.enforcement.differences %}
                    {{ policy_labels[name] }}{% if not loop.last %}, {% endif %}
                  {% endfor %}
                </span>
                {% endif %}
              </div>
              <div class="action-row">
                <a class="button-link secondary" href="{{ url_for('device_detail', mac=device.mac) }}">Ver detalle</a>
                {% if device.created %}
                <form class="trust-form" method="post" action="{{ url_for('trust_device', mac=device.mac) }}"
                      onsubmit="return confirm('{{ 'Se retirará la confianza y se restaurará la política por defecto.' if device.trusted|default(false) else 'Se permitirá comunicación local, mDNS, SSDP y broadcast para este dispositivo.' }} ¿Continuar?');">
                  <input type="hidden" name="return_to" value="dashboard">
                  <button type="submit" class="{{ 'danger-button' if device.trusted|default(false) else '' }}">
                    {{ 'Desconfiar' if device.trusted|default(false) else 'Confiar' }}
                  </button>
                </form>
                {% endif %}
              </div>
              <details class="policy-editor">
                <summary>Editar política</summary>
              <form class="policy-form" method="post"
                    action="{{ url_for('update_device_policy', mac=device.mac) }}">
                <p class="muted policy-help">mDNS, SSDP y broadcast controlan qué tráfico de descubrimiento local emitido por el dispositivo se reenvía. Interdispositivo permite conexiones unicast hacia otros dispositivos.</p>
                <div class="policy-groups">
                  <fieldset class="policy-group">
                    <legend>Conectividad</legend>
                    <div class="policy-controls connectivity">
                      <label class="policy-toggle"><input type="checkbox" name="internet" {% if device.policy.internet %}checked{% endif %}><span class="policy-toggle-copy"><span class="policy-toggle-name">Internet</span><span class="policy-toggle-state" aria-hidden="true"></span></span></label>
                      <label class="policy-toggle"><input type="checkbox" name="inter_device" {% if device.policy.inter_device %}checked{% endif %}><span class="policy-toggle-copy"><span class="policy-toggle-name">Interdispositivo</span><span class="policy-toggle-state" aria-hidden="true"></span></span></label>
                    </div>
                  </fieldset>
                  <fieldset class="policy-group">
                    <legend>Descubrimiento local</legend>
                    <div class="policy-controls discovery">
                      <label class="policy-toggle"><input type="checkbox" name="mdns" {% if device.policy.mdns %}checked{% endif %}><span class="policy-toggle-copy"><span class="policy-toggle-name">mDNS</span><span class="policy-toggle-state" aria-hidden="true"></span></span></label>
                      <label class="policy-toggle"><input type="checkbox" name="ssdp" {% if device.policy.ssdp %}checked{% endif %}><span class="policy-toggle-copy"><span class="policy-toggle-name">SSDP</span><span class="policy-toggle-state" aria-hidden="true"></span></span></label>
                      <label class="policy-toggle"><input type="checkbox" name="broadcast" {% if device.policy.broadcast in ('allow', 'log') %}checked{% endif %}><span class="policy-toggle-copy"><span class="policy-toggle-name">Broadcast</span><span class="policy-toggle-state" aria-hidden="true"></span></span></label>
                    </div>
                  </fieldset>
                </div>
                <div class="policy-actions"><button type="submit">Guardar política</button></div>
              </form>
              </details>
            </div>
          </article>
          {% endfor %}
          </div>
        </section>
        {% endif %}
      {% endfor %}
      <div class="legend">
        <span><span class="status on">verde</span> correcto o reciente</span>
        <span><span class="status warn">amarillo</span> pendiente o parcial</span>
        <span><span class="status off">rojo</span> detenido o no verificable</span>
      </div>
      {% else %}
      <div class="empty-state">Todavía no hay dispositivos registrados. Aparecerán aquí después de obtener una concesión DHCP.</div>
      {% endif %}
    </div>
  </div>
  <script>
    const policyScrollKey = "tfg-policy-scroll";
    const savedPolicyScroll = window.sessionStorage.getItem(policyScrollKey);
    if (savedPolicyScroll !== null) {
      window.requestAnimationFrame(() => {
        window.scrollTo(0, Number(savedPolicyScroll));
        window.sessionStorage.removeItem(policyScrollKey);
      });
    }

    document.addEventListener("submit", (event) => {
      if (event.target.matches(".policy-form, .trust-form")) {
        window.sessionStorage.setItem(policyScrollKey, String(window.scrollY));
      }
    });

    let dashboardRefreshRunning = false;

    async function refreshDashboard() {
      const editing = document.querySelector("details[open]") ||
        document.querySelector("input:focus, select:focus, button:focus");
      if (document.hidden || editing || dashboardRefreshRunning) return;

      dashboardRefreshRunning = true;
      try {
        const response = await fetch(window.location.href, {cache: "no-store"});
        if (!response.ok) return;

        const html = await response.text();
        const incoming = new DOMParser().parseFromString(html, "text/html");
        const refreshIds = [
          "dashboard-updated",
          "service-status-panel",
          "device-summary-panel",
          "device-list-panel",
        ];
        for (const id of refreshIds) {
          const currentNode = document.getElementById(id);
          const incomingNode = incoming.getElementById(id);
          if (currentNode && incomingNode) {
            currentNode.replaceWith(incomingNode);
          }
        }
      } catch (error) {
        // Conserva los últimos datos visibles si la Raspberry no responde.
      } finally {
        dashboardRefreshRunning = false;
      }
    }

    window.setInterval(refreshDashboard, 3000);
  </script>
</body>
</html>
"""


DEVICE_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ device.name }} · Panel TFG</title>
  <style>{{ style }}</style>
</head>
<body>
  <div class="page">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">TFG</div>
        <div><h1>{{ device.name }}</h1><p class="muted">{{ device.mac }} · {{ device.ip }} · gateway {{ device.gateway or 'sin asignar' }}</p></div>
      </div>
      <div class="toolbar">
        <span id="detail-updated" class="muted">Actualizado: {{ rendered_at }}</span>
        <a class="button-link secondary" href="{{ url_for('dashboard') }}">Volver al panel</a>
      </div>
    </header>
    {% if message %}<div class="notice success">{{ message }}</div>{% endif %}
    {% if error %}<div class="notice error">{{ error }}</div>{% endif %}

    <div id="detail-identification-panel" class="card">
      <h2>Identificación</h2>
      <p class="muted">El hostname procede del cliente DHCP y puede no ser fiable. El alias manual tiene prioridad y nunca se sobrescribe automáticamente.</p>
      <table><tbody>
        <tr><td>Nombre mostrado</td><td>{{ device.name }}</td></tr>
        <tr><td>Hostname DHCP</td><td>{{ device.hostname or 'No proporcionado' }}</td></tr>
        <tr><td>Origen del nombre</td><td>{{ {'alias': 'alias manual', 'dhcp': 'hostname DHCP', 'generated': 'identificador generado'}[device.name_source] }}</td></tr>
      </tbody></table>
      <form method="post" action="{{ url_for('update_device_name', mac=device.mac) }}">
        <label for="device-alias">Alias manual</label>
        <input id="device-alias" name="alias" maxlength="64" value="{{ device.alias or '' }}" placeholder="Ejemplo: Televisor del salón">
        <button type="submit">Guardar alias</button>
        {% if device.alias %}<button type="submit" name="alias" value="">Usar nombre detectado</button>{% endif %}
      </form>
      <details class="technical-panel">
        <summary>Información técnica de red</summary>
        <div class="technical-grid">
          <div class="technical-item"><span>Interfaz MACVLAN</span><strong>{{ device.interface }}</strong></div>
          <div class="technical-item"><span>Subred individual</span><strong>{{ device.subnet }}</strong></div>
          <div class="technical-item"><span>Gateway</span><strong>{{ device.gateway or 'sin asignar' }}</strong></div>
          <div class="technical-item"><span>Conjuntos nftables</span><strong>tfg_l2 / tfg_l3</strong></div>
        </div>
      </details>
    </div>

    <div id="detail-discovery-panel" class="card">
      <h2>Descubrimiento observado</h2>
      <div class="protocol-grid">
        {% for observation in device.observations|default([]) %}
        <div class="protocol-card">
          <h3>{% if observation.id == 'mdns' %}mDNS / Bonjour{% elif observation.id == 'ssdp' %}SSDP / UPnP{% else %}Broadcast{% endif %}</h3>
          {% if not observation.observed %}
            <span class="status neutral">No observado</span>
          {% elif observation.needs_authorization %}
            <span class="status warn">Observado · no autorizado</span>
          {% elif observation.applied %}
            <span class="status on">Observado · autorizado y aplicado</span>
          {% elif observation.enforcement_status == 'different' %}
            <span class="status warn">Observado · aplicación pendiente</span>
          {% else %}
            <span class="status off">Observado · no verificable</span>
          {% endif %}
          <p>{{ observation.events }} evento(s) en la muestra.</p>
          {% if observation.message %}<p>{{ observation.message }}</p>{% endif %}
        </div>
        {% endfor %}
      </div>
      <div class="trust-box">
        <div>
          <strong>Confianza de red local</strong>
          {% if device.trusted|default(false) %}
          <p class="muted">Este dispositivo tiene autorizado el tráfico interdispositivo,
          además de mDNS, SSDP y broadcast. Internet se controla por separado.</p>
          {% else %}
          <p class="muted">Confiar habilita el tráfico interdispositivo, mDNS, SSDP y broadcast.
          No modifica el permiso de Internet.</p>
          {% endif %}
        </div>
        {% if device.trusted|default(false) %}
        <div>
          <span class="status on">Dispositivo confiable</span>
          <form method="post" action="{{ url_for('trust_device', mac=device.mac) }}"
                onsubmit="return confirm('Se retirará la confianza y el dispositivo volverá a la política por defecto. ¿Continuar?');">
            <button class="danger-button" type="submit">Desconfiar</button>
          </form>
        </div>
        {% else %}
        <form method="post" action="{{ url_for('trust_device', mac=device.mac) }}"
              onsubmit="return confirm('Se permitirá comunicación local, mDNS, SSDP y broadcast para este dispositivo. ¿Continuar?');">
          <button type="submit">Confiar en este dispositivo</button>
        </form>
        {% endif %}
      </div>
    </div>

    <div class="detail-grid">
      <div id="detail-policy-panel" class="card">
        <h2>Política y aplicación</h2>
        <p class="muted">Comparación entre lo configurado y los conjuntos efectivos de nftables.</p>
        <form class="policy-form policy-table-form" method="post" action="{{ url_for('update_device_policy', mac=device.mac) }}">
          <input type="hidden" name="return_to" value="detail">
          <table class="policy-table">
            <thead><tr><th>Permiso</th><th>Configuración</th><th>Aplicación</th></tr></thead>
            <tbody>
            {% for name in ('internet', 'inter_device', 'mdns', 'ssdp', 'broadcast') %}
              {% set control = device.enforcement.controls.get(name, {}) %}
              <tr>
                <td class="policy-table-name">{{ policy_labels.get(name, name) }}</td>
                <td data-label="Configuración">
                  <label class="policy-table-toggle">
                    <input type="checkbox" name="{{ name }}" aria-label="Permitir {{ policy_labels.get(name, name) }}" {% if (name == 'broadcast' and device.policy.broadcast in ('allow', 'log')) or (name != 'broadcast' and device.policy.get(name)) %}checked{% endif %}>
                    <span class="policy-table-state" aria-hidden="true"></span>
                  </label>
                </td>
                <td data-label="Aplicación"><span class="status {{ 'on' if control.status == 'applied' else ('neutral' if control.status == 'inactive' else ('warn' if control.status == 'different' else 'off')) }}">{{ policy_status_labels.get(control.status, control.status) }}</span></td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
          {% if device.enforcement.error %}<details class="technical"><summary>Detalles técnicos de nftables</summary><p>{{ device.enforcement.error }}</p></details>{% endif %}
          <div class="policy-actions"><button type="submit">Guardar política</button></div>
        </form>
      </div>

      <div id="detail-activity-panel" class="card">
        <h2>Actividad observada por Zeek</h2>
        <p><span class="status {{ 'on' if device.activity.source_status == 'available' else ('warn' if device.activity.source_status == 'partial' else 'off') }}">{{ source_status_labels.get(device.activity.source_status, device.activity.source_status) }}</span></p>
        {% if device.activity.source_error %}<details class="technical"><summary>Detalles técnicos de Zeek</summary><p>{{ device.activity.source_error }}</p></details>{% endif %}
        <table>
          <tbody>
            <tr><td>Última actividad</td><td>{{ device.activity.last_seen or 'No observada' }}</td></tr>
            <tr><td>Conexiones totales de la muestra</td><td>{{ device.activity.connections }}</td></tr>
            <tr><td>Volumen</td><td>↑ {{ format_bytes(device.activity.bytes_sent) }} · ↓ {{ format_bytes(device.activity.bytes_received) }}</td></tr>
            <tr><td>Intentos Internet</td><td>{{ device.activity.external_attempts }}</td></tr>
            <tr><td>Flujos interdispositivo</td><td>{{ device.activity.peer_flows }}</td></tr>
            <tr><td>mDNS</td><td>{{ device.activity.mdns_events }}</td></tr>
            <tr><td>SSDP</td><td>{{ device.activity.ssdp_events }}</td></tr>
            <tr><td>Broadcast</td><td>{{ device.activity.broadcast_events }}</td></tr>
          </tbody>
        </table>

      </div>
    </div>

  </div>
  <script>
    const detailScrollKey = "tfg-detail-scroll";
    const savedDetailScroll = window.sessionStorage.getItem(detailScrollKey);
    if (savedDetailScroll !== null) {
      window.requestAnimationFrame(() => {
        window.scrollTo(0, Number(savedDetailScroll));
        window.sessionStorage.removeItem(detailScrollKey);
      });
    }

    document.addEventListener("submit", () => {
      window.sessionStorage.setItem(detailScrollKey, String(window.scrollY));
    });

    let detailPolicyDirty = false;
    let detailRefreshRunning = false;

    document.addEventListener("change", (event) => {
      if (event.target.closest("#detail-policy-panel .policy-form")) {
        detailPolicyDirty = true;
      }
    });

    async function refreshDeviceDetail() {
      const editing = document.querySelector("details[open]") ||
        document.querySelector("input:focus, select:focus, button:focus");
      if (document.hidden || editing || detailPolicyDirty || detailRefreshRunning) return;

      detailRefreshRunning = true;
      try {
        const response = await fetch(window.location.href, {cache: "no-store"});
        if (!response.ok) return;

        const html = await response.text();
        const incoming = new DOMParser().parseFromString(html, "text/html");
        const refreshIds = [
          "detail-updated",
          "detail-identification-panel",
          "detail-discovery-panel",
          "detail-policy-panel",
          "detail-activity-panel",
        ];
        for (const id of refreshIds) {
          const currentNode = document.getElementById(id);
          const incomingNode = incoming.getElementById(id);
          if (currentNode && incomingNode) {
            currentNode.replaceWith(incomingNode);
          }
        }
      } catch (error) {
        // Mantiene los últimos datos válidos si el dispositivo no responde.
      } finally {
        detailRefreshRunning = false;
      }
    }

    window.setInterval(refreshDeviceDetail, 3000);
  </script>
</body>
</html>
"""


def _run(command, timeout=30, capture_output=False, allow_fail=False, env=None):
    try:
        options = {
            "check": False,
            "timeout": timeout,
            "capture_output": capture_output,
            "text": capture_output,
        }
        if env is not None:
            options["env"] = env
        result = subprocess.run(command, **options)
    except (OSError, subprocess.SubprocessError) as error:
        if not allow_fail:
            print(f"No se pudo ejecutar {' '.join(command)}: {error}")
        return None
    if result.returncode != 0 and not allow_fail:
        detail = ""
        if capture_output:
            detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        print(f"Falló {' '.join(command)}{suffix}")
        return None
    return result


def _command_ok(command, **kwargs):
    return _run(command, **kwargs) is not None


def _uci_value(option, default):
    result = _run(
        ["uci", "-q", "get", option],
        capture_output=True,
        allow_fail=True,
    )
    if result and result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return default


def access_point_settings():
    """Devuelve los identificadores UCI estables del AP administrado."""
    return (
        _uci_value("tfg.main.wifi_radio", "radio0"),
        _uci_value("tfg.main.wifi_section", "wifinet1"),
    )


def resolve_access_point_interface():
    """Resuelve la interfaz runtime sin depender del número cambiante de phy."""
    radio, section = access_point_settings()
    result = _run(
        ["ubus", "call", "network.wireless", "status"],
        capture_output=True,
        allow_fail=True,
    )
    if result is None or result.returncode != 0:
        return None
    try:
        radio_status = json.loads(result.stdout).get(radio, {})
    except (TypeError, json.JSONDecodeError):
        return None
    for interface in radio_status.get("interfaces", []):
        if interface.get("section") == section:
            ifname = interface.get("ifname")
            if isinstance(ifname, str) and re.fullmatch(
                r"[a-zA-Z0-9_.-]{1,15}", ifname
            ):
                return ifname
    return None


def is_setup_complete():
    result = _run(
        ["uci", "-q", "get", SETUP_COMPLETE_OPTION],
        capture_output=True,
        allow_fail=True,
    )
    return bool(result and result.returncode == 0 and result.stdout.strip() == "1")


def set_setup_complete(complete):
    value = "1" if complete else "0"
    return _command_ok(["uci", "set", f"{SETUP_COMPLETE_OPTION}={value}"]) and (
        _command_ok(["uci", "commit", "tfg"])
    )


def remove_captive_dns_redirect():
    _run(
        ["uci", "-q", "del_list", CAPTIVE_DNS_REDIRECT],
        allow_fail=True,
    )


def configure_setup_dhcp(enabled):
    remove_captive_dns_redirect()
    ignore = "0" if enabled else "1"
    if not _command_ok(["uci", "set", f"dhcp.wifi.ignore={ignore}"]):
        return False
    if enabled and not _command_ok(
        ["uci", "add_list", CAPTIVE_DNS_REDIRECT]
    ):
        return False
    return _command_ok(["uci", "commit", "dhcp"]) and _command_ok(
        ["/etc/init.d/dnsmasq", "restart"], timeout=20
    )


def service_action(name, action, allow_fail=False):
    return _command_ok(
        [f"/etc/init.d/{name}", action],
        timeout=30,
        allow_fail=allow_fail,
    )


def service_running(name):
    result = _run(
        [f"/etc/init.d/{name}", "status"],
        timeout=10,
        capture_output=True,
        allow_fail=True,
    )
    return bool(result and result.returncode == 0)


def nft_table_available(family, table):
    result = _run(
        ["nft", "list", "table", family, table],
        timeout=10,
        capture_output=True,
        allow_fail=True,
    )
    return bool(result and result.returncode == 0)


def get_system_status():
    tables = {
        table: nft_table_available(family, table)
        for family, table in NFT_TABLES
    }
    return {
        "dhcp": service_running("tfg-dhcp"),
        "discovery": service_running("tfg-discovery"),
        "zeek": service_running("tfg-zeek"),
        "wifi_isolation": access_point_isolated(),
        "microsegmentation": all(tables.values()),
        "tables": tables,
    }


def access_point_isolated():
    _, section = access_point_settings()
    values = []
    for option in ("isolate", "bridge_isolate"):
        result = _run(
            ["uci", "-q", "get", f"wireless.{section}.{option}"],
            timeout=10,
            capture_output=True,
            allow_fail=True,
        )
        values.append(
            result.stdout.strip() if result and result.returncode == 0 else ""
        )
    return values == ["1", "1"]


def stop_normal_services():
    for service in SERVICE_NAMES:
        service_action(service, "stop", allow_fail=True)


def prepare_setup_network():
    stop_normal_services()
    for family, table in NFT_TABLES:
        _run(
            ["nft", "delete", "table", family, table],
            allow_fail=True,
        )
    return configure_setup_dhcp(True)


def prepare_normal_network():
    return configure_setup_dhcp(False)


def update_setup_state(status, step, error=None):
    with SETUP_STATE_LOCK:
        SETUP_STATE.update(status=status, step=step, error=error)


def current_setup_state():
    with SETUP_STATE_LOCK:
        return dict(SETUP_STATE)


def shutdown_legacy_router(script, password, ssid, wifi_password, brand):
    if brand == "xiaomi":
        command = [
            "python3",
            script,
            password,
            wifi_password,
            ssid,
            "off",
        ]
    else:
        command = ["python3", script, password, "off"]
    return _command_ok(command, timeout=60)


def shutdown_isp_router(router, password, username, ssid, wifi_password):
    if router["mode"] == "legacy":
        return shutdown_legacy_router(
            router["script"],
            password,
            ssid,
            wifi_password,
            router["selection"],
        )

    coordinator = RouterCoordinator()
    report = coordinator.detect(
        router["base_url"],
        allow_experimental=router["allow_experimental"],
    )
    if report.adapter is None:
        raise AdapterUnsupportedOperation(
            "Router no compatible: ningún adaptador aprobado coincide. "
            "No se ha modificado el router."
        )
    expected_adapter = router["expected_adapter"]
    if expected_adapter and report.adapter.adapter_id != expected_adapter:
        raise AdapterUnsupportedOperation(
            f"El router responde como {report.adapter.adapter_id}, no como "
            f"{expected_adapter}. No se ha modificado."
        )
    result = coordinator.disable_detected_wifi(
        report,
        Credentials(password=password, username=username or None),
    )
    return result.verification.success


def configure_access_point(ssid, wifi_password):
    radio, section = access_point_settings()
    previous_radio = _uci_value(f"wireless.{section}.device", radio)
    network = _uci_value(f"wireless.{section}.network", "wifi")
    if not re.fullmatch(r"[a-zA-Z0-9_]+", network):
        return False

    # Las secciones que crea `wifi config` no deben emitir un segundo AP.
    default_section = f"default_{radio}"
    if default_section != section:
        _command_ok(
            ["uci", "set", f"wireless.{default_section}.disabled=1"],
            timeout=10,
            allow_fail=True,
        )

    # La interfaz runtime cambia (phy4-ap0, phy5-ap0, ...). La asociación
    # wireless.<section>.network debe gestionarla netifd dinámicamente.
    _command_ok(
        ["uci", "-q", "delete", f"network.{network}.device"],
        timeout=10,
        allow_fail=True,
    )
    commands = [
        ["uci", "set", f"wireless.{radio}.disabled=0"],
    ]
    # Conserva canal y banda del AP anterior al mover el SSID a otra radio.
    for option in ("band", "channel", "htmode", "country", "txpower"):
        value = _uci_value(f"wireless.{previous_radio}.{option}", "")
        if value:
            commands.append(
                ["uci", "set", f"wireless.{radio}.{option}={value}"]
            )
    commands.extend(
        [
            ["uci", "set", f"wireless.{section}.device={radio}"],
            ["uci", "set", f"wireless.{section}.ssid={ssid}"],
            ["uci", "set", f"wireless.{section}.encryption=psk2"],
            ["uci", "set", f"wireless.{section}.key={wifi_password}"],
            ["uci", "set", f"wireless.{section}.isolate=1"],
            ["uci", "set", f"wireless.{section}.bridge_isolate=1"],
            ["uci", "set", "tfg.dhcp=service"],
            ["uci", "set", "tfg.discovery=service"],
            ["uci", "set", "tfg.zeek=service"],
            ["uci", "set", "tfg.dhcp.interface=auto"],
            ["uci", "set", "tfg.discovery.interface=auto"],
            ["uci", "set", "tfg.zeek.interface=auto"],
            ["uci", "commit", "wireless"],
            ["uci", "commit", "network"],
            ["uci", "commit", "tfg"],
            ["wifi", "reload"],
        ]
    )
    return all(_command_ok(command, timeout=30) for command in commands)


def run_network_setup():
    controller = str(PROJECT_DIR / "controlador_aut.py")
    interface = resolve_access_point_interface()
    if interface is None:
        print("No se pudo resolver la interfaz runtime del punto de acceso.")
        return False
    environment = os.environ.copy()
    environment["TFG_INTERFACE"] = interface
    configurar_interfaz_ap(interface)
    return _command_ok(
        [sys.executable, controller, "--setup-red"],
        timeout=120,
        env=environment,
    )


def start_and_wait_for_service(name, attempts=10):
    if not service_action(name, "start"):
        return False
    for _ in range(attempts):
        if service_running(name):
            return True
        time.sleep(1)
    return False


def verify_policy_tables():
    return all(nft_table_available(*table) for table in NFT_TABLES)


def recover_setup_network():
    stop_normal_services()
    set_setup_complete(False)
    return prepare_setup_network()


def complete_local_takeover(ssid, wifi_password):
    """Configure OpenWrt NORMAL mode after upstream Wi-Fi is confirmed off."""
    update_setup_state("running", "Configurando el punto de acceso OpenWrt...")
    if not configure_access_point(ssid, wifi_password):
        raise RuntimeError("No se pudo configurar o recargar el punto de acceso.")
    if not access_point_isolated():
        raise RuntimeError("El aislamiento entre estaciones Wi-Fi no quedó activo.")

    update_setup_state(
        "running",
        "Instalando las reglas base de microsegmentación...",
    )
    if not run_network_setup():
        raise RuntimeError("controlador_aut.py --setup-red no terminó correctamente.")

    update_setup_state("running", "Cambiando del DHCP temporal al controlador TFG...")
    if not configure_setup_dhcp(False):
        raise RuntimeError("No se pudo desactivar el DHCP temporal de SETUP.")

    update_setup_state("running", "Iniciando el servicio DHCP...")
    if not start_and_wait_for_service("tfg-dhcp"):
        raise RuntimeError("tfg-dhcp no alcanzó el estado running.")

    update_setup_state("running", "Iniciando el relay de descubrimiento...")
    if not start_and_wait_for_service("tfg-discovery"):
        raise RuntimeError("tfg-discovery no alcanzó el estado running.")

    update_setup_state("running", "Iniciando Zeek...")
    if not start_and_wait_for_service("tfg-zeek"):
        raise RuntimeError("tfg-zeek no alcanzó el estado running.")

    update_setup_state("running", "Verificando las tablas nftables...")
    if not verify_policy_tables():
        raise RuntimeError("No están disponibles las tablas nftables tfg_l2 y tfg_l3.")

    update_setup_state("running", "Confirmando la configuración...")
    if not set_setup_complete(True):
        raise RuntimeError("No se pudo guardar setup_complete=1 en UCI.")


def fail_takeover(error):
    recovery_ok = recover_setup_network()
    detail = str(error)
    if not recovery_ok:
        detail += " Además, no se pudo restaurar completamente la red SETUP."
    update_setup_state("error", "La configuración no se ha completado.", detail)
    print(detail)
    return False


def finalize_takeover(router, password, username, ssid, wifi_password):
    try:
        update_setup_state(
            "running",
            "Deteniendo los servicios de funcionamiento normal...",
        )
        stop_normal_services()

        update_setup_state("running", "Desactivando la Wi-Fi del router ISP...")
        if not shutdown_isp_router(
            router, password, username, ssid, wifi_password
        ):
            raise RuntimeError(
                "El router ISP no confirmó la desactivación de su Wi-Fi."
            )

        complete_local_takeover(ssid, wifi_password)

    except (AdapterError, RuntimeError) as error:
        return fail_takeover(error)

    update_setup_state(
        "success",
        "Configuración completada. Abriendo el panel...",
    )
    print("SETUP completado y verificado; el sistema está en modo NORMAL.")
    return True


def finalize_script_takeover(ssid, wifi_password):
    """Finish NORMAL setup after Codex already disabled the upstream Wi-Fi."""
    try:
        update_setup_state("running", "Deteniendo los servicios de funcionamiento normal...")
        stop_normal_services()
        complete_local_takeover(ssid, wifi_password)
    except (AdapterError, OSError, RuntimeError, ValueError) as error:
        return fail_takeover(error)

    update_setup_state("success", "Configuración completada. Abriendo el panel...")
    print("Adaptador registrado y SETUP completado; el sistema está en modo NORMAL.")
    return True


def load_devices():
    try:
        with DATABASE_PATH.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError):
        return []
    if not isinstance(document, dict):
        return []

    aliases = load_device_aliases(DEVICE_METADATA_PATH)
    devices = []
    for mac, data in sorted(document.items()):
        if not isinstance(data, dict):
            continue
        try:
            policy = obtener_politica(mac)
        except (TypeError, ValueError):
            continue
        normalized_mac = mac.lower()
        alias = aliases.get(normalized_mac)
        hostname = data.get("hostname")
        fallback_name = f"Dispositivo {normalized_mac[-8:]}"
        devices.append(
            {
                "mac": mac,
                "name": alias or hostname or fallback_name,
                "alias": alias,
                "hostname": hostname,
                "name_source": (
                    "alias" if alias else "dhcp" if hostname else "generated"
                ),
                "ip": data.get("ip_cliente", "sin asignar"),
                "gateway": data.get("ip_gateway"),
                "interface": data.get("nombre_vlan", "sin asignar"),
                "subnet": (
                    f"{str(data.get('ip_gateway')).rsplit('.', 1)[0]}.0/24"
                    if data.get("ip_gateway") else "sin asignar"
                ),
                "created": bool(data.get("creada")),
                "policy": policy,
            }
        )
    activities = load_device_activity(devices, ZEEK_LOG_DIR)
    policy_application = load_policy_application(devices)
    for device in devices:
        device["activity"] = activities[device["mac"].lower()]
        device["enforcement"] = policy_application[device["mac"].lower()]
        device["observations"] = build_protocol_observations(device)
        device["trusted"] = is_device_trusted(device["policy"])
    return devices


def _authorized_protocol_value(protocol, value):
    if protocol == "broadcast":
        return value in {"allow", "log"}
    return value is True


def build_protocol_observations(device):
    """Cruza tráfico observado, política deseada y estado efectivo."""
    activity = device.get("activity", {})
    policy = device.get("policy", {})
    controls = device.get("enforcement", {}).get("controls", {})
    observations = []
    for protocol, label, counter_name in DISCOVERY_PROTOCOLS:
        events = max(0, int(activity.get(counter_name) or 0))
        configured = policy.get(protocol)
        control = controls.get(protocol, {})
        effective = control.get("effective")
        status = control.get("status", "unavailable")
        authorized = _authorized_protocol_value(protocol, configured)
        applied = status == "applied" and _authorized_protocol_value(
            protocol, effective
        )
        message = None
        if events and not authorized:
            message = (
                "Este dispositivo necesita autorización para "
                f"descubrimiento local mediante {label}."
            )
        elif events and applied:
            message = f"{label} observado, autorizado y aplicado en nftables."
        elif events and authorized and status == "different":
            message = (
                f"{label} observado y autorizado; "
                "su aplicación está pendiente en nftables."
            )
        elif events and authorized:
            message = (
                f"{label} observado y autorizado; "
                "no se puede verificar su aplicación."
            )
        observations.append(
            {
                "id": protocol,
                "label": label,
                "events": events,
                "observed": events > 0,
                "configured": configured,
                "effective": effective,
                "enforcement_status": status,
                "authorized": authorized,
                "applied": applied,
                "needs_authorization": events > 0 and not authorized,
                "message": message,
            }
        )
    return observations


def is_device_trusted(policy):
    """La confianza es un atajo derivado, no una nueva fuente de verdad."""
    return bool(
        policy.get("inter_device")
        and policy.get("mdns")
        and policy.get("ssdp")
        and policy.get("broadcast") in ("allow", "log")
    )


def _save_json_atomic(path, document):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=4, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _runtime_client_macs():
    result = _run(
        ["nft", "list", "set", "netdev", "tfg_l2", "client_macs"],
        timeout=10,
        capture_output=True,
        allow_fail=True,
    )
    if not result or result.returncode != 0:
        return None
    return {
        match.group(0).lower()
        for match in MAC_IN_TEXT_PATTERN.finditer(result.stdout)
    }


def _cleanup_candidates(document, runtime_macs, sys_net=Path("/sys/class/net")):
    removable = []
    protected = []
    for mac, device in document.items():
        normalized_mac = str(mac).lower()
        if not isinstance(device, dict) or device.get("creada"):
            continue
        interface = device.get("nombre_vlan")
        interface_exists = bool(
            isinstance(interface, str)
            and INTERFACE_NAME_PATTERN.fullmatch(interface)
            and (Path(sys_net) / interface).exists()
        )
        if normalized_mac in runtime_macs or interface_exists:
            protected.append(mac)
        else:
            removable.append(mac)
    return removable, protected


def cleanup_inactive_devices():
    """Limpia inventario inactivo coordinándose con el proceso DHCP."""
    try:
        with DATABASE_PATH.open("r", encoding="utf-8") as stream:
            initial = json.load(stream)
    except (OSError, ValueError) as error:
        raise RuntimeError(f"No se pudo leer el inventario: {error}") from error
    if not isinstance(initial, dict):
        raise RuntimeError("El inventario de dispositivos no es válido.")
    if not any(
        isinstance(device, dict) and not device.get("creada")
        for device in initial.values()
    ):
        return {"removed": 0, "protected": 0}

    if not service_action("tfg-dhcp", "stop"):
        raise RuntimeError("No se pudo detener tfg-dhcp de forma segura.")

    failure = None
    result = None
    try:
        with DATABASE_PATH.open("r", encoding="utf-8") as stream:
            document = json.load(stream)
        if not isinstance(document, dict):
            raise RuntimeError("El inventario de dispositivos no es válido.")
        runtime_macs = _runtime_client_macs()
        if runtime_macs is None:
            raise RuntimeError("No se pudo verificar el estado activo en nftables.")
        removable, protected = _cleanup_candidates(document, runtime_macs)
        if removable:
            if not olvidar_politicas_dispositivos(removable):
                raise RuntimeError("No se pudieron limpiar las políticas específicas.")
            remove_device_aliases(removable, DEVICE_METADATA_PATH)
            for mac in removable:
                document.pop(mac, None)
            _save_json_atomic(DATABASE_PATH, document)
        result = {"removed": len(removable), "protected": len(protected)}
    except (OSError, ValueError, RuntimeError) as error:
        failure = error
    finally:
        restarted = start_and_wait_for_service("tfg-dhcp")

    if not restarted:
        raise RuntimeError("La limpieza terminó, pero tfg-dhcp no volvió a arrancar.")
    if failure is not None:
        raise RuntimeError(str(failure)) from failure
    return result


def find_device(mac, devices=None):
    """Localiza un dispositivo sin depender del formato de la MAC en la URL."""
    target = str(mac or "").lower()
    for device in load_devices() if devices is None else devices:
        if str(device.get("mac") or "").lower() == target:
            return device
    return None


def format_policy_value(value):
    """Traduce valores internos sin alterar la representación de la API."""
    if value is True:
        return "permitida"
    if value is False:
        return "bloqueada"
    if value is None:
        return "—"
    return {
        "allow": "permitida",
        "block": "bloqueada",
        "log": "permitida",
        "conflict": "conflicto",
    }.get(value, str(value))


def current_utc_label():
    """Devuelve una marca temporal breve para indicar cuándo se cargó la vista."""
    return time.strftime("%H:%M:%S UTC", time.gmtime())


def summarize_devices(devices):
    """Calcula los indicadores del panel sin consultar fuentes adicionales."""
    active = [device for device in devices if device.get("created")]
    inactive = [device for device in devices if not device.get("created")]
    return {
        "total": len(devices),
        "active": len(active),
        "inactive": len(inactive),
        "recent": sum(
            bool(device.get("activity", {}).get("recent"))
            for device in active
        ),
        "needs_authorization": sum(
            any(
                observation.get("needs_authorization")
                for observation in device.get("observations", [])
            )
            for device in active
        ),
        "policy_different": sum(
            device.get("enforcement", {}).get("status") == "different"
            for device in active
        ),
        "policy_unavailable": sum(
            device.get("enforcement", {}).get("status") == "unavailable"
            for device in active
        ),
        "zeek_limited": sum(
            device.get("activity", {}).get("source_status")
            in {"partial", "unavailable"}
            for device in active
        ),
    }


def setup_form_values(form=None, upstream_router=None):
    form = form or {}
    router_url = (form.get("router_url") or "").strip()
    if not router_url:
        upstream_router = upstream_router or discover_upstream_router()
        router_url = upstream_router.base_url if upstream_router else ""
    return {
        "router_brand": (form.get("router_brand") or "auto").strip(),
        "router_url": router_url,
        "username": (form.get("username") or "").strip(),
        "ssid": (form.get("ssid") or "").strip(),
    }


def render_setup(
    error=None,
    values=None,
    inspection=None,
    unknown_router_url=None,
):
    upstream_router = discover_upstream_router()
    return render_template_string(
        SETUP_TEMPLATE,
        style=STYLE,
        error=error,
        values=values or setup_form_values(upstream_router=upstream_router),
        inspection=inspection,
        unknown_router_url=unknown_router_url,
        upstream_router=upstream_router,
    )


def validate_setup_form(form):
    brand = (form.get("router_brand") or "").strip()
    router_url = (form.get("router_url") or "").strip()
    if not router_url:
        upstream_router = discover_upstream_router()
        router_url = upstream_router.base_url if upstream_router else ""
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    ssid = (form.get("ssid") or "").strip()
    wifi_password = form.get("wifi_password") or ""
    if brand not in ROUTER_SCRIPTS and brand not in ADAPTER_SELECTIONS:
        return None, "Selecciona un modelo de router válido."
    if not router_url:
        return None, (
            "No se pudo detectar la puerta de enlace. Introduce la URL "
            "del router manualmente."
        )
    try:
        router_url = normalize_router_url(router_url)
    except ValueError as error:
        return None, str(error)
    if not password:
        return None, "La contraseña de administración es obligatoria."
    if not ssid or len(ssid) > 32:
        return None, "El SSID debe contener entre 1 y 32 caracteres."
    if not 8 <= len(wifi_password) <= 63:
        return None, "La contraseña Wi-Fi debe contener entre 8 y 63 caracteres."
    router = {
        "selection": brand,
        "base_url": router_url,
    }
    if brand in ADAPTER_SELECTIONS:
        expected_adapter, allow_experimental = ADAPTER_SELECTIONS[brand]
        router.update(
            mode="adapter",
            expected_adapter=expected_adapter,
            allow_experimental=allow_experimental,
        )
    else:
        router.update(
            mode="legacy",
            script=str(PROJECT_DIR / "Scripts_Finales" / ROUTER_SCRIPTS[brand]),
        )
    values = {
        "router": router,
        "username": username,
        "password": password,
        "ssid": ssid,
        "wifi_password": wifi_password,
    }
    return values, None


def validate_candidate_migration_form(form):
    ssid = (form.get("ssid") or "").strip()
    wifi_password = form.get("wifi_password") or ""
    if not ssid or len(ssid) > 32:
        return None, "El SSID debe contener entre 1 y 32 caracteres."
    if not 8 <= len(wifi_password) <= 63:
        return None, "La contraseña Wi-Fi debe contener entre 8 y 63 caracteres."
    return {
        "ssid": ssid,
        "wifi_password": wifi_password,
    }, None


@app.route("/")
def index():
    if is_setup_complete():
        return redirect(url_for("dashboard"))
    return redirect(url_for("setup"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if is_setup_complete():
        return redirect(url_for("dashboard"))

    state = current_setup_state()
    if request.method == "GET":
        if state["status"] == "running":
            return render_template_string(PROGRESS_TEMPLATE, style=STYLE)
        return render_setup(
            error=state["error"] if state["status"] == "error" else None,
        )

    values, error = validate_setup_form(request.form)
    if error:
        return (
            render_setup(
                error=error,
                values=setup_form_values(request.form),
            ),
            400,
        )

    with SETUP_STATE_LOCK:
        if SETUP_STATE["status"] == "running":
            return (
                render_template_string(PROGRESS_TEMPLATE, style=STYLE),
                202,
            )
        SETUP_STATE.update(
            status="running",
            step="Preparando la migración...",
            error=None,
        )

    try:
        worker = threading.Thread(
            target=finalize_takeover,
            args=(
                values["router"],
                values["password"],
                values["username"],
                values["ssid"],
                values["wifi_password"],
            ),
            daemon=True,
        )
        worker.start()
    except RuntimeError as thread_error:
        update_setup_state(
            "error",
            "No se pudo iniciar la migración.",
            str(thread_error),
        )
        return (
            render_setup(
                error=str(thread_error),
                values=setup_form_values(request.form),
            ),
            500,
        )

    return render_template_string(PROGRESS_TEMPLATE, style=STYLE), 202


@app.route("/setup/router/inspect", methods=["POST"])
def inspect_setup_router():
    if is_setup_complete():
        return redirect(url_for("dashboard"))

    wants_json = request.accept_mimetypes.best == "application/json"
    values, error = validate_setup_form(request.form)
    public_values = setup_form_values(request.form)
    if error:
        if wants_json:
            return jsonify(ok=False, error=error), 400
        return render_setup(error=error, values=public_values), 400
    router = values["router"]
    if router["mode"] != "adapter":
        error = (
            "La compatibilidad legacy no ofrece inspección común. "
            "Selecciona detección automática o un adaptador."
        )
        if wants_json:
            return jsonify(ok=False, error=error), 400
        return (
            render_setup(
                error=error,
                values=public_values,
            ),
            400,
        )

    try:
        inspection = RouterCoordinator().inspect(
            router["base_url"],
            Credentials(
                password=values["password"],
                username=values["username"] or None,
            ),
            allow_experimental=router["allow_experimental"],
        )
        if not inspection.supported:
            error = "Router no compatible: no se ha realizado ningún cambio."
            if wants_json:
                return jsonify(
                    ok=False,
                    error=error,
                    unknown_router=True,
                ), 422
            return (
                render_setup(
                    error=error,
                    values=public_values,
                    unknown_router_url=router["base_url"],
                ),
                422,
            )
        expected_adapter = router["expected_adapter"]
        if expected_adapter and inspection.adapter_id != expected_adapter:
            raise AdapterUnsupportedOperation(
                f"El router detectado es {inspection.adapter_id}, no "
                f"{expected_adapter}."
            )
    except AdapterError as adapter_error:
        if wants_json:
            return jsonify(ok=False, error=str(adapter_error)), 422
        return (
            render_setup(
                error=str(adapter_error),
                values=public_values,
            ),
            422,
        )

    if wants_json:
        return jsonify(
            ok=True,
            adapter_id=inspection.adapter_id,
            wifi=inspection.status.wifi.value,
            dhcp=inspection.status.dhcp.value,
        )
    return render_setup(values=public_values, inspection=inspection)


@app.route("/setup/router/discovery", methods=["POST"])
def start_router_discovery():
    if is_setup_complete():
        return redirect(url_for("dashboard"))
    try:
        router_url = normalize_router_url(request.form.get("router_url") or "")
        mode = (request.form.get("mode") or "assisted").strip()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ssid = (request.form.get("ssid") or "").strip()
        wifi_password = request.form.get("wifi_password") or ""
        if not password:
            raise ValueError("La contraseña del router es obligatoria.")
        if not ssid or len(ssid) > 32:
            raise ValueError("El SSID debe contener entre 1 y 32 caracteres.")
        if not 8 <= len(wifi_password) <= 63:
            raise ValueError("La contraseña Wi-Fi debe contener entre 8 y 63 caracteres.")
        if service_running("tfg-ai-discovery"):
            raise RuntimeError("Ya hay un descubrimiento en ejecución.")
        job = create_job(
            router_url,
            mode=mode,
            state_dir=AI_STATE_DIR,
            credentials_dir=AI_CREDENTIALS_DIR,
            username=username or None,
            password=password,
            ssid=ssid,
            wifi_password=wifi_password,
        )
        job_id = job["job_id"]
        configured = _command_ok(
            ["uci", "set", f"tfg.ai.job_id={job_id}"]
        ) and _command_ok(["uci", "commit", "tfg"])
        started = configured and service_action("tfg-ai-discovery", "start")
        if not started:
            discard_job_credentials(job_id, AI_CREDENTIALS_DIR)
            update_job(
                AI_STATE_DIR / "jobs" / job_id,
                "failed",
                "No se pudo iniciar el servicio tfg-ai-discovery.",
            )
            raise RuntimeError("No se pudo iniciar el servicio de descubrimiento.")
    except (OSError, RuntimeError, ValueError) as error:
        return render_setup(error=str(error)), 503

    return redirect(url_for("router_discovery_page", job_id=job_id))


@app.route("/setup/discovery/<job_id>")
def router_discovery_page(job_id):
    if is_setup_complete():
        return redirect(url_for("dashboard"))
    try:
        read_job(job_id, AI_STATE_DIR)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return render_setup(error="Trabajo de descubrimiento no encontrado."), 404
    return render_template_string(
        DISCOVERY_TEMPLATE,
        style=STYLE,
        job_id=job_id,
        project_dir=str(PROJECT_DIR),
        error=None,
    )


@app.route("/setup/discovery/<job_id>/migrate", methods=["POST"])
def migrate_discovered_router(job_id):
    if is_setup_complete():
        return redirect(url_for("dashboard"))
    try:
        discovery = read_job(job_id, AI_STATE_DIR)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return render_setup(error="Trabajo de descubrimiento no encontrado."), 404

    values, error = validate_candidate_migration_form(request.form)
    if discovery.get("status") != "script_ready":
        error = "La integración todavía no ha terminado correctamente."
    if error:
        return render_template_string(
            DISCOVERY_TEMPLATE,
            style=STYLE,
            job_id=job_id,
            project_dir=str(PROJECT_DIR),
            error=error,
        ), 400

    with SETUP_STATE_LOCK:
        if SETUP_STATE["status"] == "running":
            return render_template_string(PROGRESS_TEMPLATE, style=STYLE), 202
        SETUP_STATE.update(
            status="running",
            step="Preparando la migración con el adaptador generado...",
            error=None,
        )
    try:
        worker = threading.Thread(
            target=finalize_script_takeover,
            args=(
                values["ssid"],
                values["wifi_password"],
            ),
            daemon=True,
        )
        worker.start()
    except RuntimeError as thread_error:
        update_setup_state("error", "No se pudo iniciar la migración.", str(thread_error))
        return render_template_string(
            DISCOVERY_TEMPLATE,
            style=STYLE,
            job_id=job_id,
            project_dir=str(PROJECT_DIR),
            error=str(thread_error),
        ), 500
    return render_template_string(PROGRESS_TEMPLATE, style=STYLE), 202


@app.route("/setup/discovery/<job_id>/status")
def router_discovery_status(job_id):
    if is_setup_complete():
        return jsonify({"mode": "NORMAL"}), 409
    try:
        return jsonify(read_job(job_id, AI_STATE_DIR))
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return jsonify({"error": "discovery job not found"}), 404


@app.route("/setup/status")
def setup_status():
    state = current_setup_state()
    state["setup_complete"] = is_setup_complete()
    return jsonify(state)


@app.route("/dashboard")
def dashboard():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    devices = load_devices()
    devices.sort(key=lambda device: not bool(device.get("created")))
    return render_template_string(
        DASHBOARD_TEMPLATE,
        style=STYLE,
        status=get_system_status(),
        devices=devices,
        summary=summarize_devices(devices),
        format_bytes=format_byte_count,
        policy_labels=POLICY_LABELS,
        policy_status_labels=POLICY_STATUS_LABELS,
        source_status_labels=SOURCE_STATUS_LABELS,
        format_policy=format_policy_value,
        rendered_at=current_utc_label(),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@app.route("/api/status")
def api_status():
    if not is_setup_complete():
        return jsonify({"mode": "SETUP"}), 409
    return jsonify({"mode": "NORMAL", **get_system_status()})


@app.route("/api/devices")
def api_devices():
    if not is_setup_complete():
        return jsonify({"mode": "SETUP", "devices": []}), 409
    return jsonify({"mode": "NORMAL", "devices": load_devices()})


@app.route("/api/devices/<mac>")
def api_device(mac):
    if not is_setup_complete():
        return jsonify({"mode": "SETUP"}), 409
    device = find_device(mac)
    if device is None:
        return jsonify({"error": "device not found"}), 404
    return jsonify({"mode": "NORMAL", "device": device})


@app.route("/devices/<mac>")
def device_detail(mac):
    if not is_setup_complete():
        return redirect(url_for("setup"))
    device = find_device(mac)
    if device is None:
        return "Dispositivo no encontrado.", 404
    return render_template_string(
        DEVICE_TEMPLATE,
        style=STYLE,
        device=device,
        format_bytes=format_byte_count,
        policy_labels=POLICY_LABELS,
        policy_status_labels=POLICY_STATUS_LABELS,
        source_status_labels=SOURCE_STATUS_LABELS,
        format_policy=format_policy_value,
        rendered_at=current_utc_label(),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@app.route("/devices/<mac>/policy", methods=["POST"])
def update_device_policy(mac):
    if not is_setup_complete():
        return redirect(url_for("setup"))
    changes = {
        "internet": request.form.get("internet") == "on",
        "inter_device": request.form.get("inter_device") == "on",
        "mdns": request.form.get("mdns") == "on",
        "ssdp": request.form.get("ssdp") == "on",
        "broadcast": (
            "allow" if request.form.get("broadcast") == "on" else "block"
        ),
    }
    return_to_detail = request.form.get("return_to") == "detail"
    endpoint = "device_detail" if return_to_detail else "dashboard"
    endpoint_values = {"mac": mac} if return_to_detail else {}
    if actualizar_politica(mac, **changes):
        endpoint_values["message"] = (
            "Política guardada; el controlador la aplicará "
            "en su siguiente recarga."
        )
        return redirect(url_for(endpoint, **endpoint_values))
    endpoint_values["error"] = (
        "No se pudo validar, guardar o aplicar la política."
    )
    return redirect(url_for(endpoint, **endpoint_values))


@app.route("/devices/<mac>/trust", methods=["POST"])
def trust_device(mac):
    if not is_setup_complete():
        return redirect(url_for("setup"))
    device = find_device(mac)
    if device is None:
        return "Dispositivo no encontrado.", 404

    return_to_dashboard = request.form.get("return_to") == "dashboard"
    endpoint = "dashboard" if return_to_dashboard else "device_detail"
    endpoint_values = {} if return_to_dashboard else {"mac": mac}

    if is_device_trusted(device["policy"]):
        success = restaurar_politica_por_defecto(mac)
        if success:
            endpoint_values["message"] = (
                "Confianza retirada: el dispositivo vuelve a usar "
                "la política restrictiva por defecto."
            )
        else:
            endpoint_values["error"] = (
                "No se pudo restaurar la política por defecto."
            )
    else:
        success = actualizar_politica(
            mac,
            inter_device=True,
            mdns=True,
            ssdp=True,
            broadcast="allow",
        )
        if success:
            endpoint_values["message"] = (
                "Confianza aplicada: comunicación local, mDNS, SSDP "
                "y broadcast autorizados."
            )
        else:
            endpoint_values["error"] = (
                "No se pudo guardar la política de confianza."
            )
    return redirect(url_for(endpoint, **endpoint_values))


@app.route("/devices/inactive/cleanup", methods=["POST"])
def cleanup_inactive():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    try:
        result = cleanup_inactive_devices()
    except RuntimeError as error:
        return redirect(url_for("dashboard", error=str(error)))
    message = f"Se eliminaron {result['removed']} dispositivo(s) inactivo(s)."
    if result["protected"]:
        message += f" {result['protected']} entrada(s) se conservaron por seguridad."
    return redirect(url_for("dashboard", message=message))


@app.route("/devices/<mac>/name", methods=["POST"])
def update_device_name(mac):
    if not is_setup_complete():
        return redirect(url_for("setup"))
    if find_device(mac) is None:
        return "Dispositivo no encontrado.", 404
    try:
        update_device_alias(mac, request.form.get("alias"), DEVICE_METADATA_PATH)
    except (OSError, ValueError) as error:
        return redirect(url_for("device_detail", mac=mac, error=str(error)))
    return redirect(
        url_for("device_detail", mac=mac, message="Alias actualizado.")
    )


@app.route("/<path:path>")
def catch_all(path):
    if is_setup_complete():
        return redirect(url_for("dashboard"))
    return redirect(url_for("setup"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portal y panel web del TFG")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", default=80, type=int)
    args = parser.parse_args(argv)

    if is_setup_complete():
        if not prepare_normal_network():
            print("No se pudo preparar la red para el modo NORMAL.")
            return 1
        mode = "NORMAL"
    else:
        if not prepare_setup_network():
            print("No se pudo preparar la red cautiva para el modo SETUP.")
            return 1
        mode = "SETUP"

    print(
        f"Iniciando tfg-web en {args.listen}:{args.port}, modo {mode}. "
        "uhttpd debe usar un puerto distinto."
    )
    app.run(
        host=args.listen,
        port=args.port,
        debug=False,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
