# Microsegmentación dinámica para redes domésticas

Prototipo de Trabajo Fin de Grado para aplicar microsegmentación por dispositivo
en una red doméstica mediante una Raspberry Pi con OpenWrt. El sistema sustituye
el punto de acceso Wi-Fi del router original, actúa como puerta de enlace y
servidor DHCP, y asigna a cada cliente una subred IPv4 y una interfaz MACVLAN
propias.

El objetivo es bloquear por defecto la comunicación lateral entre clientes y
habilitar de forma explícita Internet, tráfico entre dispositivos y servicios
de descubrimiento local necesarios, sin instalar software en los equipos de la
vivienda.

> **Aviso de seguridad.** Este repositorio contiene software que modifica la
> configuración de red, firewall y Wi-Fi de OpenWrt, y scripts que pueden
> desactivar el Wi-Fi de routers domésticos. No ejecute los puntos de entrada ni
> los scripts de router en un ordenador de uso diario. Utilice hardware de
> prueba, una copia de la configuración y credenciales de laboratorio.

## Capacidades

- Aprovisionamiento DHCP y asignación de una subred IPv4 por cliente.
- Creación y reconciliación de interfaces MACVLAN y reglas de firewall.
- Política por dispositivo para Internet, comunicación entre clientes, mDNS,
  SSDP y broadcast IPv4 autorizado.
- Aislamiento Wi-Fi y relay con lista de protocolos permitidos para evitar que
  el tráfico directo entre estaciones eluda las políticas.
- Portal Flask para el modo de incorporación inicial y el panel de operación.
- Observabilidad de actividad mediante Zeek y comprobación del estado efectivo
  de nftables.
- Integraciones para routers GL.iNet, Mercusys, Xiaomi y ZTE, junto con un
  mecanismo controlado de descubrimiento de integraciones adicionales.

## Arquitectura

```text
Clientes Wi-Fi
     │  (aislamiento entre estaciones)
     ▼
Raspberry Pi + OpenWrt
 ├── Portal web: SETUP y panel de políticas
 ├── DHCP: inventario, subred e interfaz MACVLAN por cliente
 ├── nftables: control de capa 2 y capa 3
 ├── Relay: mDNS, SSDP y broadcast autorizados
 └── Zeek: actividad observada
     │
     ▼
Router doméstico / salida a Internet
```

La identidad operativa se basa en la dirección MAC observada en el AP. El
prototipo se limita deliberadamente a IPv4; IPv6 se bloquea para evitar rutas
que el plano de políticas no controle.

## Estructura

| Ruta | Contenido |
| --- | --- |
| `controlador_aut.py` | DHCP, ciclo de vida e inventario de dispositivos. |
| `interfaces_creator.py` | MACVLAN, UCI y firewall base. |
| `policy_manager.py` / `policy_observer.py` | Renderizado, aplicación y verificación de políticas nftables. |
| `setup_portal.py` | Portal de incorporación y panel de administración. |
| `discovery_relay.py` | Relay restringido de mDNS, SSDP y broadcast IPv4. |
| `router_adapters/` | Contrato y adaptadores de routers. |
| `Scripts_Finales/` | Switchers y documentación de las integraciones legacy. |
| `openwrt/` | Servicios procd, configuración UCI y diagnóstico. |
| `tui/` | Monitorización de tráfico en terminal. |
| `tests/` | Pruebas automatizadas sin necesidad de router o Raspberry Pi. |

## Requisitos

Para desarrollo y pruebas locales se necesita Python 3.11 o posterior:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest tests
```

Para ejecutar el sistema se requiere una Raspberry Pi con OpenWrt, un adaptador
Wi-Fi compatible con `mac80211` y soporte de aislamiento entre estaciones. Se
necesitan además las utilidades de OpenWrt `ip`, `uci`, `nft`, `wifi` y los
servicios indicados en `openwrt/`. Zeek es opcional para la observabilidad, no
para la aplicación de políticas.

La radio integrada de algunas Raspberry Pi, especialmente con `brcmfmac`, no
ofrece una garantía adecuada de aislamiento entre estaciones; el diagnóstico
del proyecto la rechaza para no declarar un aislamiento no verificable.

## Validación local

Las pruebas sustituyen las operaciones de red, ficheros del router y comandos
del sistema por dobles de prueba. No configuran interfaces reales.

```powershell
python -m compileall controlador_aut.py interfaces_creator.py setup_portal.py router_adapters Scripts_Finales
python -m pytest tests
```

La última validación local del repositorio completó 246 pruebas correctamente.

## Despliegue en OpenWrt

Revise primero la configuración y la topología real del equipo. Las órdenes
siguientes describen el flujo de instalación; ejecútelas únicamente en la
Raspberry Pi de pruebas:

```sh
mkdir -p /usr/libexec /etc/init.d
cp /root/tfg/openwrt/tfg-service-runner /usr/libexec/
cp /root/tfg/openwrt/tfg-resolve-ap-interface /usr/libexec/
cp /root/tfg/openwrt/tfg-ai-discovery-runner /usr/libexec/
cp /root/tfg/openwrt/tfg-web /root/tfg/openwrt/tfg-dhcp /root/tfg/openwrt/tfg-discovery /root/tfg/openwrt/tfg-zeek /root/tfg/openwrt/tfg-ai-discovery /etc/init.d/
cp /root/tfg/openwrt/tfg.config /etc/config/tfg
chmod 755 /usr/libexec/tfg-* /etc/init.d/tfg-*
```

El detalle de opciones UCI, puertos, habilitación de servicios y diagnóstico se
encuentra en [`openwrt/README.md`](openwrt/README.md). Antes de iniciar el
portal en el puerto 80, compruebe la configuración actual de `uhttpd` para no
perder acceso a LuCI.

El flujo normal es:

1. Arrancar `tfg-web` en modo SETUP (`setup_complete=0`).
2. Inspeccionar el router ascendente y configurar el AP con las credenciales
   que se desean conservar.
3. Desactivar y verificar el Wi-Fi del router doméstico.
4. Crear la red gestionada, iniciar DHCP, relay y Zeek, y comprobar las tablas
   `tfg_l2` y `tfg_l3`.
5. Confirmar el modo NORMAL (`setup_complete=1`) solo tras las verificaciones.

El sistema intenta recuperar el DHCP y DNS cautivos si falla la incorporación,
pero no implementa un rollback completo del Wi-Fi o de la configuración del
router ascendente.

## Configuración y datos locales

`database.json` y `policies.json` son estado de ejecución. No incluya en un
repositorio público MAC, IP, nombres de equipos, SSID, contraseñas, capturas ni
logs procedentes de una red real. Para una entrega reproducible, use valores
sintéticos y mantenga las configuraciones reales fuera del control de versiones. Los ejemplos `database.example.json` y `policies.example.json` muestran el formato inicial.

Las credenciales de router se introducen durante la incorporación; no deben
pasarse por argumentos de línea de comandos ni guardarse en el repositorio.

## Limitaciones

- La implementación controla IPv4; no ofrece microsegmentación IPv6.
- La identidad se basa en MAC, por lo que la aleatorización de MAC puede crear
  una nueva identidad para el mismo cliente.
- La compatibilidad con routers depende de su firmware e interfaz de gestión.
- Los permisos de descubrimiento no conceden automáticamente la comunicación
  unicast posterior: esta sigue sujeta a la política de clientes.
