
# Clase de Hacking

## Clase del 30-10-2024

### Recolección de Información / Reconocimiento
- **Google Dorks**: Técnicas para realizar búsquedas avanzadas en Google y descubrir información específica.
- **Shodan**: Motor de búsqueda para dispositivos conectados a internet.
- **Robtex**: Herramienta de análisis de red y DNS.
- **DNSDumpster**: Herramienta para obtener información de DNS y mapa de red.
- **nslookup**: Comando para consultas de DNS.
- **dig**: Alternativa avanzada a `nslookup` para consultas de DNS.
- **Maltego**: Herramienta de análisis de inteligencia y conexiones entre nodos.
- **The Harvester**: Herramienta para recolectar correos y nombres de dominio.
- **AutoReconTool (Recon-NG)**:  Framework de reconocimiento modular que permite realizar tareas de recolección de información avanzada.

### Enumeración / Escaneo
- `ping`: Comando para comprobar la conectividad con un dispositivo en la red.
- `arp-scan`: Escaneo de red para descubrir dispositivos conectados.
- **AutoRecon**: Herramienta de escaneo automático de red y vulnerabilidades.
- **Netdiscover**: Herramienta para descubrir hosts en la red local.
- `nmap -vv -sV -sC -O -p 445`: Escaneo con Nmap para detección de servicios, versiones y sistema operativo en el puerto 445.
- Navegar a los scripts de Nmap:
  ```bash
  cd /usr/share/nmap/scripts
  ```

## Clase del 31-10-2024 - Cómo Evadir un Firewall

### Técnicas de Evasión en Nmap
- **MTU (`--mtu`)**: Ajusta el tamaño de los paquetes enviados para evitar detección, configurando la unidad de transmisión máxima.
- **Data Length (`--data-length`)**: Ajusta manualmente la longitud de los datos para hacerlos lo suficientemente cortos y evitar detección.
- **Source Port (`--source-port`)**: Configura manualmente el puerto de origen para evadir detección, permitiendo seleccionar un puerto específico.
- **Decoy (`-D`)**: Envía paquetes falsos para confundir los sistemas de detección y ocultar actividad real.
- **Fragmented (`-f`)**: Fragmenta los paquetes para evitar que el firewall reconozca el tráfico como escaneo.
- **Spoof-Mac (`--spoof-mac`)**: Cambia la dirección MAC para evitar detección.
- **Stealth Scan (`-sS`)**: Realiza un escaneo SYN que evita establecer una conexión completa, ayudando a evadir detección.
- **Min-Rate (`--min-rate`)**: Controla la velocidad de los paquetes enviados, permitiendo disminuir el ritmo para evadir detección.

#### Comandos de Evasión Populares
- **Top Evasion**:
  - `--source-port`
  - `-D`
  - `--spoof-mac`
  - `-sS`
  - `--min-rate`

#### Ejemplo de Comando Evasivo
```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
nmap -sCV -p80,443,21 <IP>
```

### Ejemplos y Explicaciones
- **Three-Way Handshake**: Secuencia de conexión TCP (SYN, SYN-ACK, ACK).
- **RST**: Señal para finalizar una conexión TCP.

## Clase del 01-11-2024

### Enumeración y Escaneo de SMB y SNMP
- **smbclient**: Similar a `crackmapexec`, permite conectarse a recursos compartidos SMB. Las carpetas con `$` son predefinidas (usadas para gestión y mantenimiento).
- **enum4linux**: Herramienta para enumerar usuarios a través de SMB en el puerto 445.
- **nbtscan**: Lista equipos en la red a través de NetBIOS (puerto TCP 139).
- **snmpwalk**: Lista dispositivos en una red mediante el protocolo SNMP (puertos UDP 161 y 162).
- **arp-scan**: Alternativa a `snmpwalk`, útil para detectar dispositivos en la red sin depender de puertos.

## Hacking – Post-Explotación

### Herramientas para Post-Explotación
- **WinPEAS**: Para detectar vulnerabilidades en sistemas Windows.
- **LinPEAS**: Similar a WinPEAS, pero para sistemas Linux.
- **Gtfobins**: Herramienta para identificar binarios en sistemas Linux que pueden utilizarse para escalación de privilegios.
- **Lolbas**: Lista de binarios en Windows que pueden usarse en ataques post-explotación.
- **Bashark**: Framework de post-explotación para entornos Linux.
- **Mimikatz**: Herramienta para la extracción de contraseñas y tokens en sistemas Windows.
- **Empire**: Framework de post-explotación y explotación de Windows.
- **Msfvenom**: Herramienta de Metasploit para generar payloads personalizados.

### Herramientas Generales de Post-Explotación
- **Metasploit (msfconsole)**: Framework para explotación y post-explotación de vulnerabilidades.

### Decodificación y Codificación

#### Base64
```bash
echo "Qm9iIC0gIVBAJCRXMHJEITEyMw" | base64 --decode
```
Resultado:
```
Bob - !P@$sW0rD!123
```

### Protocolos y Puertos Importantes
- **LDAP**: Utilizado por Active Directory para comunicación entre equipos.
- **NetBIOS**: Protocolo de Windows para comunicación en red, reemplazado en gran parte por SMB.
- **Protocolo de Escritorio Remoto (RDP)**: Utilizado para acceder y controlar de forma remota equipos Windows en redes locales y a través de internet, generalmente en el puerto 3389.

## Herramientas Resumidas

### Resumen de Comandos y Herramientas
- **Reconocimiento**: Google Dorks, Shodan, Robtex, DNSDumpster, nslookup, dig, Maltego, The Harvester.
- **Escaneo Básico**: ping, arp-scan, nmap, AutoRecon, Netdiscover.
- **Enumeración y Escaneo de SMB/SNMP**: smbclient, enum4linux, snmpwalk, nbtscan.
- **Evasión de Firewall en Nmap**: Técnicas de ajuste de MTU, Source Port, Decoy, Fragmented, Stealth Scan y otras técnicas.
- **Post-Explotación**: WinPEAS, LinPEAS, Gtfobins, Lolbas, Bashark, Mimikatz, Empire, Msfvenom.
- **Framework General**: Metasploit (msfconsole).
- **Decodificación Base64**: Método para decodificar y codificar en formato base64.
