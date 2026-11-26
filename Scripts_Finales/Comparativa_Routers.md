# Análisis Comparativo: Dificultad de Automatización y Medidas de Seguridad en Routers ISP

A continuación se presenta una evaluación comparativa de los routers analizados en este estudio, clasificados de menor a mayor dificultad técnica de cara a la ingeniería inversa y su posterior automatización mediante scripts nativos (Python).

---

## Nivel 1: ZTE ZXHN H298A V1.0
**Nivel de Dificultad:** Medio-Bajo

Este router representa un enfoque clásico de seguridad web embebida. Su barrera de entrada no es criptográfica, sino estructural (basada en Server-Side Rendering).

* **Ingeniería Inversa:** Sencilla. El tráfico viaja en gran medida en texto plano (formularios URL-encoded), lo que facilita su intercepción directa con herramientas como Wireshark o DevTools.
* **Mecanismos de Defensa:**
  * **Hashing simple:** Protege la contraseña en tránsito concatenándola con un _seed_ dinámico y aplicando SHA-256.
  * **CSRF vía Scraping:** El mayor reto para la automatización es que el servidor inyecta tokens efímeros ofuscados (`_sessionTmpToken`) dentro del código fuente HTML de ciertas páginas. Para enviar un comando, el script debe emular un _parser_ HTML y limpiar secuencias de escape hexadecimales.
* **Veredicto:** Es un sistema tradicional. Una vez localizado el token temporal en el código fuente, la orquestación es directa.

---

## Nivel 2: ZTE F6705
**Nivel de Dificultad:** Alta

Este modelo da un salto evolutivo importante, combinando seguridad asimétrica con un control de flujo de usuario muy restrictivo (Anti-Bot).

* **Ingeniería Inversa:** Compleja. Exigió el uso de frameworks de instrumentación de navegadores reales (Playwright) como paso intermedio para capturar el árbol de peticiones exacto que realiza la interfaz, dado que la inspección estática del código no revelaba los estados del servidor.
* **Mecanismos de Defensa:**
  * **Cifrado RSA del Payload:** No acepta variables en plano. Obliga al script a extraer claves públicas inyectadas en el JavaScript, aplicar _padding_ PKCS1 v1.5 y codificar el payload de configuración en Base64.
  * **Máquina de Estados (Page-Context):** Su característica más sofisticada. No basta con estar autenticado y tener la firma RSA correcta. Si el backend no tiene un registro cronológico de que el usuario ha solicitado visualmente (`GET menuView`) las páginas HTML donde residen los botones antes de recibir el `POST`, rechaza la petición con un error interno (`SessionTimeout`).
  * **Tokens Efímeros de Interacción:** Cada navegación lógica revoca la validez del token de sesión para escritura, obligando a solicitar refrescos constantes del token principal.
* **Veredicto:** El reto de este router no fueron las matemáticas, sino la ingeniería de su arquitectura de red: obligar al script a "imitar" a un ser humano navegando por la web para alinear la máquina de estados del backend.

---

## Nivel 3: Mercusys / Ecosistema TP-Link
**Nivel de Dificultad:** Extrema

A nivel de seguridad de cliente-servidor web, este router presenta una arquitectura asombrosamente compleja que rivaliza con protocolos empresariales cerrados. Abandona la filosofía del contexto de página y lo apuesta todo a una coraza criptográfica impecable de extremo a extremo.

* **Ingeniería Inversa:** Muy elevada. Requiere analizar, desofuscar y replicar miles de líneas de JavaScript cliente que actúan como un cliente criptográfico (Implementando AES y RSA localmente en el navegador sin depender exclusivamente de TLS).
* **Mecanismos de Defensa (Criptografía Híbrida Customizada):**
  * **Intercambio Dinámico de Claves:** El router emite dos pares de claves RSA distintos: uno para cifrar contraseñas y otro para validar firmas de integridad.
  * **Cifrado Simétrico Total:** El script de Python debe generar claves AES de 16-bytes y Vectores de Inicialización (IV) aleatorios para cada petición. *Toda* la carga útil viaja cifrada por AES, y las respuestas del router también vienen cifradas, por lo que el script debe descifrarlas para saber si tuvo éxito.
  * **Anti-Replay Attacks (Secuencias y Firmas):** Para evitar que alguien intercepte un paquete cifrado y lo reenvíe, el router exige llevar la cuenta de un Número de Secuencia (bytes enviados) y adjuntar una Firma RSA combinando hashes MD5, el IV de AES y la secuencia actual.
* **Veredicto:** Automatizar este router equivale a desarrollar un cliente VPN/TLS desde cero en la capa de aplicación. Es una proeza de desarrollo (y una anomalía por su enorme robustez para el ámbito doméstico) que exige un dominio alto de librerías criptográficas de bajo nivel.

---

## Nivel 4: GL.iNet (Ecosistema OpenWrt puro)
**Nivel de Dificultad:** Profesional / Nativo

A diferencia de los modelos comerciales enfocados al usuario final, este router abraza su naturaleza OpenWrt ofreciendo interfaces pensadas para la interconexión de sistemas embebidos.

* **Ingeniería Inversa:** Metódica. No hay ofuscación maliciosa en el código, sino una arquitectura cliente-servidor real (Vue.js contra JSON-RPC).
* **Mecanismos de Defensa:**
  * **Challenge-Response:** El backend exige superar un desafío para evitar ataques de fuerza bruta y de reenvío. El router devuelve una sal (`salt`) y un número de un solo uso (`nonce`).
  * **Shadow Hash de Linux:** Utiliza el estándar de cifrado nativo de sistemas POSIX (`SHA-256 Crypt` con 5000 iteraciones). El cliente simula la creación del hash como si de `/etc/shadow` se tratase.
  * **API ubus:** Una vez autenticados, se utiliza el bus de mensajes interno de OpenWrt (`ubus`) enviando comandos estructurados en JSON, sin tener que "hackear" vistas HTML.
* **Veredicto:** Es el modelo más limpio y agradecido para trabajar. Combina una altísima seguridad contra bots (gracias a los _nonces_ dinámicos y algoritmos iterativos) con una arquitectura transparente y sin trampas (sin *Page-Context*).

---

## Nivel 5: Xiaomi Mi Router 4C (MiWiFi)
**Nivel de Dificultad:** Alta (Monolítico y Fat-Client)

El firmware MiWiFi es un _fork_ heavily modificado de OpenWrt (usando LuCI). Combina un backend tradicional con una seguridad de frontend muy idiosincrásica.

* **Ingeniería Inversa:** Moderada, pero analítica. El cifrado recae totalmente sobre el lado del cliente (Navegador).
* **Mecanismos de Defensa:**
  * **Nonce Autogenerado:** A diferencia de GL.iNet donde el servidor emite el desafío, en Xiaomi es el propio cliente el que se inventa el desafío concatenando la dirección MAC, un *Timestamp* Unix y una variable aleatoria.
  * **Cifrado Multi-Capa (Doble SHA-1):** Utiliza una llave maestra incrustada en el código fuente de la web y aplica rondas encadenadas de SHA-1.
  * **Validación Temporal (Anti-Replay):** El servidor desarma el *nonce* que le envía el cliente y compara el *Timestamp* incrustado con el reloj del sistema operativo del router para abortar peticiones caducadas.
  * **Reutilización de Endpoints:** No tiene un endpoint específico para el botón de apagado, sino que intercepta toda la configuración actual de las antenas, exige recibir la contraseña Wi-Fi en texto plano y re-configura todo el archivo `hostapd` internamente.
* **Veredicto:** Interesante ejercicio de arquitectura donde el servidor delega la carga computacional y de generación de identificadores al cliente, validando únicamente la frescura temporal de las matemáticas.
