# Servicios OpenWrt del TFG

El sistema utiliza cuatro servicios permanentes y un trabajo bajo demanda
supervisados por procd:

- tfg-web: portal SETUP y panel NORMAL permanente.
- tfg-dhcp: controlador DHCP y aprovisionamiento dinámico.
- tfg-discovery: relay de mDNS, SSDP y broadcast autorizado por emisor.
- tfg-zeek: observabilidad de tráfico.
- tfg-ai-discovery: generación y prueba puntual de integraciones con Codex.

El antiguo servicio agregador /etc/init.d/tfg ya no se instala porque
duplicaba el proceso DHCP.

## Instalación

    mkdir -p /usr/libexec /etc/init.d
    cp /root/tfg/openwrt/tfg-service-runner /usr/libexec/tfg-service-runner
    cp /root/tfg/openwrt/tfg-resolve-ap-interface /usr/libexec/tfg-resolve-ap-interface
    cp /root/tfg/openwrt/tfg-ai-discovery-runner /usr/libexec/tfg-ai-discovery-runner
    cp /root/tfg/openwrt/tfg-web /etc/init.d/tfg-web
    cp /root/tfg/openwrt/tfg-dhcp /etc/init.d/tfg-dhcp
    cp /root/tfg/openwrt/tfg-discovery /etc/init.d/tfg-discovery
    cp /root/tfg/openwrt/tfg-zeek /etc/init.d/tfg-zeek
    cp /root/tfg/openwrt/tfg-ai-discovery /etc/init.d/tfg-ai-discovery
    cp /root/tfg/openwrt/tfg.config /etc/config/tfg
    chmod 755 /usr/libexec/tfg-service-runner \
        /usr/libexec/tfg-resolve-ap-interface \
        /usr/libexec/tfg-ai-discovery-runner /etc/init.d/tfg-*

    /etc/init.d/tfg-web enable
    /etc/init.d/tfg-dhcp enable
    /etc/init.d/tfg-discovery enable
    /etc/init.d/tfg-zeek enable

tfg-ai-discovery no se habilita en el arranque: tfg-web lo inicia solamente
cuando existe un trabajo de descubrimiento.

## Diagnóstico de despliegue

`openwrt/tfg-diagnostics` realiza una comprobación de solo lectura adaptada al
modo SETUP o NORMAL. Revisa servicios, puerto 80, tablas nftables, logs Zeek y
la respuesta del portal. Puede ejecutarse directamente con:

    sh /root/tfg/openwrt/tfg-diagnostics

Devuelve un código distinto de cero cuando encuentra fallos. Los pasos de
actualización y prueba están en
`docs/experiments/openwrt_runtime_validation.md`.

En una instalación existente conviene actualizar las opciones mediante UCI
para no sobrescribir ajustes locales:

    uci -q delete tfg.main
    uci set tfg.main=main
    uci set tfg.main.setup_complete='0'
    uci set tfg.main.wifi_radio='radio0'
    uci set tfg.main.wifi_section='wifinet1'
    uci -q delete tfg.web
    uci set tfg.web=service
    uci set tfg.web.project_dir='/root/tfg'
    uci set tfg.web.python='/usr/bin/python3'
    uci set tfg.web.listen='0.0.0.0'
    uci set tfg.web.port='80'
    uci -q delete tfg.discovery
    uci set tfg.discovery=service
    uci set tfg.discovery.project_dir='/root/tfg'
    uci set tfg.discovery.python='/usr/bin/python3'
    uci set tfg.discovery.interface='auto'
    uci set tfg.discovery.reload_interval='2'
    uci set tfg.discovery.rate_limit='20'
    uci set tfg.zeek.binary='/opt/zeek/bin/zeek'
    uci -q delete tfg.ai
    uci set tfg.ai=service
    uci set tfg.ai.project_dir='/root/tfg'
    uci set tfg.ai.python='/usr/bin/python3'
    uci set tfg.ai.codex_binary='/usr/bin/codex'
    uci set tfg.ai.codex_home='/root/.codex'
    uci set tfg.ai.dns_servers='1.1.1.1 8.8.8.8'
    uci set tfg.ai.state_dir='/var/lib/tfg-ai'
    uci set tfg.ai.integrations_dir='/etc/tfg-ai/integrations'
    uci set tfg.ai.discovery_mode='assisted'
    uci commit tfg

setup_complete=0 activa el modo SETUP. Los servicios DHCP, discovery y Zeek omiten su
arranque automático durante el boot, pero mantienen disponible la operación
manual start que usa el portal durante la migración. Solo después de validar
los tres servicios, el aislamiento Wi-Fi y las tablas tfg_l2 y tfg_l3, el portal confirma
setup_complete=1.

## Puertos de Flask y LuCI

tfg-web escucha permanentemente en el puerto HTTP 80. No detiene, inicia ni
reconfigura uhttpd; la separación de puertos se prepara una sola vez durante
la instalación.

Antes de cambiar nada, inspecciona la configuración real:

    uci show uhttpd | grep listen

La opción recomendada es conservar HTTPS de LuCI en 443 y mover únicamente su
listener HTTP de 80 a 8081. Los nombres y valores exactos deben adaptarse a la
salida anterior. Un ejemplo habitual es:

    uci -q del_list uhttpd.main.listen_http='0.0.0.0:80'
    uci -q del_list uhttpd.main.listen_http='[::]:80'
    uci add_list uhttpd.main.listen_http='0.0.0.0:8081'
    uci add_list uhttpd.main.listen_http='[::]:8081'
    uci commit uhttpd
    /etc/init.d/uhttpd restart

Después:

- Panel TFG: http://IP_GESTION/
- LuCI HTTPS: https://IP_GESTION/
- LuCI HTTP alternativo: http://IP_GESTION:8081/

No ejecutes el ejemplo a ciegas si uci show uhttpd utiliza listeners distintos.

## Funcionamiento

En SETUP, tfg-web mantiene activo el DHCP temporal de dnsmasq y la redirección
DNS cautiva. La finalización:

1. desactiva la Wi-Fi del router ISP;
2. configura y recarga el AP de OpenWrt;
3. ejecuta explícitamente
   python3 /root/tfg/controlador_aut.py --setup-red;
4. desactiva el DHCP temporal;
5. inicia y verifica tfg-dhcp, tfg-discovery y tfg-zeek;
6. comprueba las dos tablas nftables;
7. confirma setup_complete=1.

Si falla, mantiene setup_complete=0, detiene los servicios normales y trata de
restaurar el DHCP y DNS cautivos. No intenta todavía un rollback completo del
router ISP o de la configuración Wi-Fi.

En NORMAL, el mismo Flask muestra estado, inventario y controles de políticas.
Las políticas se guardan atómicamente en policies.json; el controlador las
recarga y aplica sin reiniciar cada dos segundos.

Los servicios obtienen la interfaz runtime a partir de `tfg.main.wifi_radio`
y `tfg.main.wifi_section`. El resolver busca esa sección concreta dentro de
la radio, sin depender de que sea la primera. Esto evita guardar nombres
variables como `phy4-ap0`: `radio1` y `wifinet1` siguen siendo identificadores
estables aunque el USB reaparezca como otro `phy`.

El AP debe utilizar un driver mac80211 compatible y configura `isolate=1` y
`bridge_isolate=1`, por lo que mac80211 no puede
copiar tráfico directamente entre estaciones antes del filtrado del host.
`tfg-discovery` escucha la copia recibida por la Raspberry y reinyecta
únicamente mDNS, SSDP y broadcast IPv4 autorizados por la política del emisor.
Nunca retransmite ARP, DHCP, EAPOL, IPv6 ni tráfico desconocido. Un permiso de
SSDP permite emitir descubrimiento, pero la respuesta y el control unicast
siguen dependiendo de la política `Clientes`. Si el servicio se detiene, el
aislamiento del AP permanece activo y el sistema falla de forma cerrada.
La radio integrada de Raspberry con `brcmfmac` no garantiza esta propiedad:
el diagnóstico la rechaza para no presentar como efectivo un aislamiento que
el firmware puede ignorar.

El panel asocia las direcciones del inventario con una muestra acotada de
conn.log y dns.log. Muestra última actividad, conexiones, volumen, protocolos,
destinos y consultas DNS observadas; Zeek no aplica ni modifica políticas. La
ruta compartida se configura con tfg.zeek.log_dir y cada lectura se limita a
los últimos 2 MiB y 2000 registros por archivo para no cargar logs completos.
La interfaz diferencia una fuente disponible sin tráfico, datos parciales
(solo uno de los logs) y una fuente Zeek no verificable.

Para cada dispositivo activo, el panel compara además la política configurada
con los conjuntos efectivos de tfg_l2 y tfg_l3. Consulta ambas tablas nftables
en modo de solo lectura, con JSON cuando está disponible y salida textual como
compatibilidad. El resultado distingue política aplicada, diferente, no
verificable o dispositivo inactivo. La actividad clasificada como Internet,
clientes, mDNS, SSDP o broadcast representa intentos observados por Zeek; no
demuestra por sí sola que nftables los haya permitido.

El nombre de cada dispositivo enlaza con `/devices/<MAC>`, donde se presenta
la trazabilidad completa de política configurada, estado efectivo y muestra
Zeek. La misma información está disponible individualmente en
`/api/devices/<MAC>`. El procedimiento de prueba reproducible está documentado
en `docs/experiments/policy_observability_validation.md`.

La presentación no depende de recursos externos: toda la identidad visual y
el diseño adaptable están incluidos en la plantilla Flask. El dashboard deja
los destinos y consultas DNS para la vista individual, ofrece el editor de
políticas de forma plegable, traduce los estados técnicos y muestra la hora de
carga. Así mantiene un resumen legible sin ocultar la evidencia detallada.

El dashboard calcula un resumen únicamente a partir del inventario ya cargado:
total, activos, inactivos y dispositivos con actividad reciente. También avisa
si una política activa difiere de nftables, no puede verificarse o la fuente
Zeek está incompleta. Los dispositivos activos se muestran antes que los
inactivos, sin alterar el orden ni la estructura de `/api/devices`.

El controlador conserva además el `hostname` opcional enviado por el cliente
en DHCP. La web puede asignarle un alias humano desde `/devices/<MAC>` y lo
guarda separadamente en `/etc/tfg/device_aliases.json`, mediante reemplazo
atómico. Así `controlador_aut.py` continúa siendo el único escritor de
`database.json` y se evitan carreras entre DHCP y Flask. La prioridad visible
es alias manual, hostname DHCP e identificador corto derivado de la MAC.

## Adaptadores y descubrimiento Codex

El formulario SETUP permite detectar GL.iNet y Xiaomi mediante adaptadores
aprobados. Mercusys mantiene la ruta legacy y ofrece además su adaptador como
opción experimental; los ZTE continúan temporalmente como compatibilidad
legacy. La comprobación del router es read-only y no inicia la migración.

La URL del router se rellena automáticamente usando la puerta de enlace IPv4
local con menor métrica de la Raspberry Pi. Esta operación solo consulta la
tabla de rutas: no escanea la subred ni contacta con otros dispositivos. El
campo permanece editable para redes con varias rutas o topologías especiales.
Si una sonda falla por un error transitorio, el registro realiza un segundo
intento breve antes de considerar que el adaptador no coincide.

Si no coincide ninguna integración, el portal crea un trabajo en
`/var/lib/tfg-ai/jobs`. El modo `assisted`, recomendado para uso real, entrega
a Codex los adaptadores y scripts legacy existentes como referencias. El modo
`clean_room` se conserva para las evaluaciones académicas sin esas pistas.

El portal entrega al trabajo las credenciales del router y el SSID/clave Wi-Fi
que debe conservar la Raspberry. Se guardan con permisos 600 en
`/tmp/tfg-ai-credentials`, nunca en `request.json`, y el runner los elimina al
terminar o recibir una señal. Codex se ejecuta de
forma efímera con sandbox workspace-write y acceso de red habilitado. Puede
analizar el router y las referencias, crear scripts, autenticarse, probar
hipótesis y ejecutar el apagado Wi-Fi real. La única limitación funcional del
prompt es no modificar DHCP, WAN, credenciales ni la red de la Raspberry.

La salida ya no tiene que implementar todo `RouterAdapter`. Codex genera un
`candidate/switcher.py` con tres acciones pequeñas: `detect`, `status` y `off`.
Todas devuelven JSON, y `status`/`off` reciben las credenciales por stdin para
que no aparezcan en argv. Codex ejecuta el script, espera la convergencia y solo
declara éxito si una nueva lectura confirma todas las radios desactivadas.

Durante ese trabajo, tfg-ai-discovery sustituye temporalmente únicamente el
resolvedor local de la Raspberry. Usa primero los servidores configurados en
`tfg.ai.dns_servers` y conserva como respaldo los upstream aprendidos por
OpenWrt; esto evita depender de DNS defectuosos anunciados por un router. No
modifica la resolución de los clientes ni la redirección de dnsmasq, por lo que
estos continúan en el portal cautivo. Un trap restaura el resolvedor al
finalizar o recibir una señal; tfg-web recupera además cualquier copia
pendiente antes de arrancar tras una interrupción anómala.

Comprueba primero la instalación y autenticación local ya usada por Codex:

    command -v codex
    codex exec --ephemeral "Responde solo: OK"

El servicio declara explícitamente HOME=/root y CODEX_HOME=/root/.codex porque
procd no hereda necesariamente el entorno de una sesión SSH. Solo proporciona
la ruta al caché autenticado existente; no copia, registra ni expone auth.json.

Adapta `tfg.ai.codex_binary` si `command -v` muestra otra ruta. Al terminar
Codex, el sistema comprueba la sintaxis y los archivos de resultado, vuelve a
ejecutar `detect` y `status`, y exige que el estado observado sea `disabled`.
Solo entonces guarda el script en `/etc/tfg-ai/integrations` y añade al
manifiesto su identificador y SHA-256. Los trabajos permanecen en
`/var/lib/tfg-ai/jobs` y las credenciales en `/tmp/tfg-ai-credentials`, pero el
registro validado se conserva en el overlay persistente de OpenWrt. Al arrancar
`tfg-web`, una instalación anterior se migra desde
`/var/lib/tfg-ai/integrations` y `/var/lib/tfg-ai/approved` si todavía no existe
el registro equivalente en `/etc/tfg-ai`. Si el registro temporal ya se perdió,
las integraciones versionadas en `docs/experiments/generated_integrations` se
restauran como segunda fuente. Ninguna de estas rutas sobrescribe un manifiesto
persistente ya existente.

Tras registrar el script, el mismo servicio usa el SSID y la clave Wi-Fi
temporales para ejecutar automáticamente la secuencia normal: configurar el AP,
`--setup-red`, sustituir el DHCP temporal, iniciar DHCP/Zeek, verificar nftables
y marcar `setup_complete=1`. Codex no utiliza esos dos campos contra el router.
En siguientes instalaciones, el registro envuelve el script guardado como un
adaptador aprobado y prueba primero su acción `detect`; si coincide, ejecuta
`status/off` directamente sin volver a iniciar Codex.

## Control y logs

    /etc/init.d/tfg-web start|stop|restart|status
    /etc/init.d/tfg-dhcp start|stop|restart|status
    /etc/init.d/tfg-discovery start|stop|restart|status
    /etc/init.d/tfg-zeek start|stop|restart|status
    /etc/init.d/tfg-ai-discovery start|stop|status

Los logs y PID se guardan en:

- /var/log/tfg/web.log, /var/run/tfg/web.pid
- /var/log/tfg/dhcp.log, /var/run/tfg/dhcp.pid
- /var/log/tfg/zeek/, /var/run/tfg/zeek.pid
- /var/log/tfg/ai-discovery.log

El arranque normal de tfg-dhcp no reconstruye firewall, UCI, rutas ni MACVLAN.
Fuera del portal, la reconstrucción explícita continúa disponible:

    python3 /root/tfg/controlador_aut.py --setup-red
