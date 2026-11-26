import json
import argparse
import os
import subprocess
import threading
import tempfile
import time
import re
from scapy.all import *
from interfaces_creator import (
    crear_macvlan,
    eliminar_macvlan,
    reconciliar_interfaces_firewall,
)
from policy_manager import (
    configurar_politicas_base,
    eliminar_dispositivo,
    obtener_clientes_runtime,
    recargar_politicas,
    reconciliar_dispositivos,
    registrar_dispositivo,
)

def _entero_entorno(nombre, defecto, minimo):
    """Lee un entero de configuración y usa el valor por defecto si no es válido."""
    valor = os.environ.get(nombre)
    if valor is None or valor.strip() == "":
        return defecto
    try:
        numero = int(valor)
    except ValueError:
        print(f"AVISO: {nombre}={valor!r} no es un entero; se usa {defecto}.")
        return defecto
    if numero < minimo:
        print(f"AVISO: {nombre}={numero} es menor que {minimo}; se usa {defecto}.")
        return defecto
    return numero


INTERFACE = os.environ.get("TFG_INTERFACE", "phy0-ap0")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.json")

# Concesión DHCP y retirada de los segmentos cuya concesión caduca sin renovarse.
LEASE_TIME = _entero_entorno("TFG_LEASE_TIME", 3600, 60)
LEASE_EXPIRY_ENABLED = os.environ.get("TFG_LEASE_EXPIRY", "1").strip() != "0"
LEASE_GRACE = 60
LEASE_CHECK_INTERVAL = 30

# Sincronización del inventario y de las operaciones de red.
db_lock = threading.RLock()
os_lock = threading.Lock()
en_creacion = set()
pending_requests = {}
PENDING_REQUEST_TTL = 60
POLICY_RELOAD_INTERVAL = 2
MAX_HOSTNAME_LENGTH = 253
INTERFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,14}$")

try:
    with open(DB_PATH, 'r') as f:
        DISPOSITIVOS = json.load(f)
except FileNotFoundError:
    print("AVISO: No se encuentra database.json, se creará uno nuevo.")
    DISPOSITIVOS = {}

def guardar_bbdd():
    # La llamada debe mantener adquirido db_lock.
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(DB_PATH), text=True)
    with os.fdopen(fd, 'w') as f:
        json.dump(DISPOSITIVOS, f, indent=4)
    os.replace(temp_path, DB_PATH)


def interfaz_en_padre_actual(interface):
    """Comprueba que una MACVLAN existente cuelga del AP seleccionado."""
    try:
        with open(f"/sys/class/net/{interface}/iflink", encoding="ascii") as stream:
            parent_index = int(stream.read().strip())
        with open(f"/sys/class/net/{INTERFACE}/ifindex", encoding="ascii") as stream:
            expected_index = int(stream.read().strip())
    except (OSError, ValueError):
        return False
    return parent_index == expected_index


def reconciliar_estado_runtime():
    """Alinea inventario, MACVLAN, zona firewall y políticas al arrancar."""
    active_devices = {}
    active_interfaces = []
    runtime_states = {}
    nft_clients = obtener_clientes_runtime()
    with db_lock:
        for mac, device in DISPOSITIVOS.items():
            interface = device.get("nombre_vlan")
            exists = bool(
                isinstance(interface, str)
                and INTERFACE_NAME_RE.fullmatch(interface)
                and os.path.exists(os.path.join("/sys/class/net", interface))
            )
            active = exists and interfaz_en_padre_actual(interface) and (
                bool(device.get("creada")) or mac.lower() in nft_clients
            )
            runtime_states[mac] = active
            if active:
                active_interfaces.append(interface)
                active_devices[mac] = {
                    "client_ip": device.get("ip_cliente"),
                    "gateway_ip": device.get("ip_gateway"),
                }

    with os_lock:
        if not reconciliar_interfaces_firewall(active_interfaces):
            return False
        if not reconciliar_dispositivos(active_devices):
            return False

    with db_lock:
        changed = False
        now = time.time()
        for mac, exists in runtime_states.items():
            if bool(DISPOSITIVOS[mac].get("creada")) != exists:
                DISPOSITIVOS[mac]["creada"] = exists
                changed = True
            # Un segmento activo sin fecha de concesión dispone de una concesión
            # completa para renovarla antes de poder retirarse.
            if exists and not isinstance(
                DISPOSITIVOS[mac].get("ultima_concesion"), (int, float)
            ):
                DISPOSITIVOS[mac]["ultima_concesion"] = now
                changed = True
        if changed:
            guardar_bbdd()
    return True

def es_mac_valida(mac):
    return re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) is not None


def normalizar_hostname(value):
    """Normaliza el hostname opcional enviado por un cliente DHCP."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    if not isinstance(value, str):
        return None
    hostname = " ".join(value.replace("\x00", "").split())
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        return None
    if not all(character.isprintable() for character in hostname):
        return None
    return hostname

def nuevo_dispositivo(mac):
    nombre_vlan = f"v_{mac.replace(':', '')}"

    with db_lock:
        subredes_usadas = set(int(d["ip_gateway"].split(".")[2]) for d in DISPOSITIVOS.values())
        siguiente_red = 10
        while siguiente_red in subredes_usadas:
            siguiente_red += 1

        if siguiente_red > 254:
            print(f"No quedan subredes disponibles para {mac}")
            return False

        ip_gateway = f"192.168.{siguiente_red}.1"
        ip_cliente = f"192.168.{siguiente_red}.100"
        DISPOSITIVOS[mac] = {
            "nombre_vlan": nombre_vlan,
            "ip_gateway": ip_gateway,
            "ip_cliente": ip_cliente,
            "creada": False
        }
        guardar_bbdd()

    print(f"Nuevo dispositivo registrado: {mac} en subred {siguiente_red}")
    return True


def craft_dhcp_response(pkt, msg_type_str, device_info):
    ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(INTERFACE))
    ip = IP(src=device_info["ip_gateway"], dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)

    yiaddr_val = "0.0.0.0" if msg_type_str == "nak" else device_info["ip_cliente"]

    bootp = BOOTP(op=2, yiaddr=yiaddr_val, siaddr=device_info["ip_gateway"],
            chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
    dhcp = DHCP(options=[
        ("message-type", msg_type_str),
        ("server_id", device_info["ip_gateway"]),
        ("subnet_mask", "255.255.255.0"),
        ("router", device_info["ip_gateway"]),
        ("name_server", "8.8.8.8"),
        ("lease_time", LEASE_TIME),
        "end"
    ])
    return ether / ip / udp / bootp / dhcp


def aprovisionar_dispositivo(mac, device):
    """Crea la red y completa cualquier DHCP Request que estaba esperando."""
    provisioning_started = time.monotonic()
    try:
        print(f"Creando MACVLAN en segundo plano para {mac}...")
        with os_lock:
            exito = crear_macvlan(
                device["nombre_vlan"],
                device["ip_gateway"],
            )
            if exito:
                exito = registrar_dispositivo(
                    mac,
                    device["ip_cliente"],
                    device["ip_gateway"],
                )
            if not exito:
                eliminar_macvlan(device["nombre_vlan"])

        if not exito:
            print(f"Falló la creación de MACVLAN para {mac}")
            with db_lock:
                pending_requests.pop(mac, None)
            return

        request_pkt = None
        with db_lock:
            DISPOSITIVOS[mac]["creada"] = True
            DISPOSITIVOS[mac]["ultima_concesion"] = time.time()
            guardar_bbdd()

            req_data = pending_requests.pop(mac, None)
            if req_data is not None:
                request_age = time.monotonic() - req_data["time"]
                if request_age < PENDING_REQUEST_TTL:
                    request_pkt = req_data["pkt"]
                else:
                    print(f"La petición DHCP pendiente ha caducado para {mac}")

        elapsed = time.monotonic() - provisioning_started
        print(
            f"Red MACVLAN y políticas listas para {mac} "
            f"en {elapsed:.2f} s"
        )
        if request_pkt is not None:
            print(f"Enviando el ACK de la petición pendiente para {mac}")
            ack_pkt = craft_dhcp_response(request_pkt, "ack", device)
            sendp(ack_pkt, iface=INTERFACE, verbose=False)
    finally:
        with db_lock:
            en_creacion.discard(mac)


def iniciar_aprovisionamiento(mac):
    """Reserva y lanza una sola reconstrucción para la MAC indicada."""
    with db_lock:
        device = DISPOSITIVOS.get(mac)
        if device is None or device["creada"] or mac in en_creacion:
            return False
        en_creacion.add(mac)
        device_snapshot = dict(device)

    try:
        threading.Thread(
            target=aprovisionar_dispositivo,
            args=(mac, device_snapshot),
            daemon=True,
        ).start()
    except RuntimeError as error:
        with db_lock:
            en_creacion.discard(mac)
        print(f"No se pudo iniciar el aprovisionamiento de {mac}: {error}")
        return False
    return True


def dhcp(pkt):
    if DHCP not in pkt or BOOTP not in pkt or Ether not in pkt:
        return

    # Solo se procesan mensajes DHCP enviados por clientes.
    if pkt[BOOTP].op != 1:
        return

    mac_origen = pkt[Ether].src.lower()
    if not es_mac_valida(mac_origen):
        return

    with db_lock:
        if mac_origen not in DISPOSITIVOS:
            if not nuevo_dispositivo(mac_origen):
                return # No se continúa si no hay una asignación disponible.

        device = DISPOSITIVOS[mac_origen]

    msg_type = None
    requested_ip = None
    hostname = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type":
                msg_type = opt[1]
            elif opt[0] == "requested_addr":
                requested_ip = opt[1]
            elif opt[0] in {"hostname", "client_FQDN"}:
                hostname = normalizar_hostname(opt[1]) or hostname

    if hostname:
        with db_lock:
            if DISPOSITIVOS[mac_origen].get("hostname") != hostname:
                DISPOSITIVOS[mac_origen]["hostname"] = hostname
                guardar_bbdd()

    if msg_type == 1: # Discover
        print(f"DHCP Discover de {mac_origen}.")
        # La oferta se envía antes de iniciar el aprovisionamiento.
        offer_pkt = craft_dhcp_response(pkt, "offer", device)
        sendp(offer_pkt, iface=INTERFACE, verbose=False)

        iniciar_aprovisionamiento(mac_origen)

    elif msg_type == 3: # Request
        ciaddr = pkt[BOOTP].ciaddr
        client_asking_ip = requested_ip if requested_ip else ciaddr

        if (
            client_asking_ip
            and client_asking_ip != "0.0.0.0"
            and client_asking_ip != device["ip_cliente"]
        ):
            print(f"DHCP NAK: {mac_origen} solicitó IP incorrecta ({client_asking_ip}).")
            nak_pkt = craft_dhcp_response(pkt, "nak", device)
            sendp(nak_pkt, iface=INTERFACE, verbose=False)
        else:
            with db_lock:
                creada = device["creada"]
                if not creada:
                    pending_requests[mac_origen] = {
                        "pkt": pkt,
                        "time": time.monotonic(),
                    }

            # El ACK espera a que la red del dispositivo esté preparada.
            if creada:
                print(f"DHCP ACK: confirmación de IP ({device['ip_cliente']}) para {mac_origen}")
                ack_pkt = craft_dhcp_response(pkt, "ack", device)
                sendp(ack_pkt, iface=INTERFACE, verbose=False)
                with db_lock:
                    pending_requests.pop(mac_origen, None)
                    DISPOSITIVOS[mac_origen]["ultima_concesion"] = time.time()
                    guardar_bbdd()
            else:
                print(f"DHCP Request de {mac_origen} pendiente hasta que termine la creación de la MACVLAN.")
                iniciar_aprovisionamiento(mac_origen)

    elif msg_type == 7: # Release
        print(f"DHCP Release: {mac_origen} ha enviado una liberación de su dirección IP.")
        with db_lock:
            DISPOSITIVOS[mac_origen]["creada"] = False
            pending_requests.pop(mac_origen, None)
            guardar_bbdd()

        def bg_eliminar():
            with os_lock:
                eliminar_dispositivo(mac_origen)
                eliminar_macvlan(device["nombre_vlan"])

        threading.Thread(target=bg_eliminar, daemon=True).start()

def vigilar_politicas(stop_event):
    """Comprueba el JSON sin competir con el aprovisionamiento de la red."""
    while not stop_event.wait(POLICY_RELOAD_INTERVAL):
        with os_lock:
            recargar_politicas()


STATION_RE = re.compile(r"^Station\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")


def estaciones_asociadas():
    """Devuelve las MAC asociadas al AP, o None si no puede consultarse."""
    try:
        result = subprocess.run(
            ["iw", "dev", INTERFACE, "station", "dump"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        print(f"No se pudieron consultar las estaciones asociadas: {error}")
        return None
    if result.returncode != 0:
        print("No se pudieron consultar las estaciones asociadas.")
        return None
    stations = set()
    for line in result.stdout.splitlines():
        match = STATION_RE.match(line.strip())
        if match:
            stations.add(match.group(1).lower())
    return stations


def concesion_caducada(device, now):
    """Indica si un segmento creado lleva más de una concesión sin renovarse."""
    last = device.get("ultima_concesion")
    if not device.get("creada") or not isinstance(last, (int, float)):
        return False
    return now - last > LEASE_TIME + LEASE_GRACE


def revisar_concesiones():
    """Retira los segmentos de clientes ausentes cuya concesión ha caducado.

    Solo se retira un segmento si su concesión ha caducado y el equipo ya no
    está asociado al AP. Si la asociación no puede comprobarse, no se retira
    nada. La entrada del inventario se conserva para que el equipo recupere su
    subred y su política si vuelve.
    """
    now = time.time()
    with db_lock:
        candidates = [
            mac
            for mac, device in DISPOSITIVOS.items()
            if mac not in en_creacion and concesion_caducada(device, now)
        ]
    if not candidates:
        return []

    stations = estaciones_asociadas()
    if stations is None:
        return []

    retired = []
    for mac in candidates:
        if mac in stations:
            continue
        # os_lock se adquiere antes de marcar el segmento para que un
        # aprovisionamiento posterior espere a que termine la retirada.
        with os_lock:
            with db_lock:
                device = DISPOSITIVOS.get(mac)
                if (
                    device is None
                    or mac in en_creacion
                    or not concesion_caducada(device, time.time())
                ):
                    continue
                device["creada"] = False
                pending_requests.pop(mac, None)
                guardar_bbdd()
                interface = device["nombre_vlan"]
            print(f"Concesión caducada para {mac}; se retira su segmento.")
            eliminar_dispositivo(mac)
            eliminar_macvlan(interface)
        retired.append(mac)
    return retired


def vigilar_concesiones(stop_event):
    """Revisa periódicamente las concesiones sin interrumpir el servicio DHCP."""
    while not stop_event.wait(LEASE_CHECK_INTERVAL):
        try:
            revisar_concesiones()
        except Exception as error:  # El hilo no debe detenerse por un fallo puntual.
            print(f"Error al revisar las concesiones: {error}")


def setup_red():
    """Instala explícitamente las reglas base de red y políticas."""
    if not configurar_politicas_base():
        raise SystemExit("No se pudo configurar el gestor de políticas Layer 2/3.")
    if not reconciliar_estado_runtime():
        raise SystemExit(
            "No se pudieron recuperar las interfaces activas tras configurar la red."
        )
    print("Configuración base de red y políticas instalada.")


def servir_dhcp():
    """Ejecuta el bucle DHCP sin reconfigurar la red existente."""
    if not reconciliar_estado_runtime():
        raise RuntimeError(
            "No se pudo reconciliar el estado de red antes de iniciar DHCP."
        )
    print(
        f"Escuchando DHCP en {INTERFACE}; "
        "estado de firewall y políticas reconciliado."
    )

    stop_event = threading.Event()
    threading.Thread(
        target=vigilar_politicas, args=(stop_event,), daemon=True
    ).start()
    print("Recarga automática de policies.json cada 2 segundos.")
    if LEASE_EXPIRY_ENABLED:
        threading.Thread(
            target=vigilar_concesiones, args=(stop_event,), daemon=True
        ).start()
        print(
            f"Concesiones de {LEASE_TIME} s; los segmentos sin renovar se "
            "retiran si el cliente ya no está asociado."
        )
    else:
        print(f"Concesiones de {LEASE_TIME} s; retirada automática desactivada.")
    print("Esperando peticiones DHCP...")
    try:
        sniff(iface=INTERFACE, filter="udp and (port 67 or 68)", prn=dhcp, store=0)
    finally:
        stop_event.set()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Controlador DHCP de microsegmentación"
    )
    parser.add_argument(
        "--setup-red",
        action="store_true",
        help="instala o reconstruye explícitamente firewall y políticas base",
    )
    args = parser.parse_args([] if argv is None else argv)
    if args.setup_red:
        setup_red()
        return
    servir_dhcp()


if __name__ == "__main__":
    main(sys.argv[1:])
