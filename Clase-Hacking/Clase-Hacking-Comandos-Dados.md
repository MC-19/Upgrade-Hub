
# Clase de Hacking

## Clase del 30-10-2024
  Recolección de información / Reconocimiento

  Google Dorks

Shodan

Robtex

DNSDumpster

Nslookup

Dig

Maltego

The Harvester


Enumeración / Escaneo
### Comandos Básicos
- `ping`: Comando para comprobar la conectividad con un dispositivo en la red.
- `arp-scan`: Escaneo de red para descubrir dispositivos conectados.
- `nmap -vv -sV -sC -O -p 445`: Escaneo con Nmap para detección de servicios, versiones y sistema operativo en el puerto 445.
- Navegar a los scripts de Nmap:
  ```bash
  cd /usr/share/nmap/scripts
  ```

## Clase del 31-10-2024 - Cómo Evadir un Firewall

### Técnicas de Evasión en Nmap
- **`--source-port`**: Especifica un puerto de origen para evadir ciertos firewalls.
- **`-D`**: Genera tráfico falso con direcciones IP falsas (decoys).
- **`--spoof-mac`**: Cambia la dirección MAC de origen.
- **`-sS`**: SYN-Scan, realiza solo el SYN del Three-Way Handshake.
- **`--min-rate`**: Define el mínimo de paquetes enviados por segundo.
- **`--mtu`**: Ajusta el tamaño de la unidad de transmisión (mínimo 8 + suma mínima de Nmap = 20).

#### Ejemplo de Comando Evasivo
```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
nmap -sCV -p80,443,21 <IP>
```

### Opciones Avanzadas
- **`--data-length`**: Define la longitud de los paquetes.
- **`-f`**: Fragmenta los paquetes para dificultar la detección.
- **`--source-port 80`**: Usa el puerto 80 como puerto de origen; útil si el puerto 80 no está bloqueado.
- **`-D (Decoy)`**: Envía paquetes falsos con IPs falsas.
- **`--spoof-mac`**: Cambia la dirección MAC de origen.
- **`-sS`**: SYN-Scan, realiza solo el SYN del Three-Way Handshake.
- **`--min-rate`**: Define el mínimo de paquetes enviados por segundo.

### Ejemplos y Explicaciones
- **Three-Way Handshake**: Secuencia de conexión TCP (SYN, SYN-ACK, ACK).
- **RST**: Señal para finalizar una conexión TCP.

## Herramientas para la Enumeración de Redes y Sistemas

### smbclient
- Similar a `crackmapexec`.
- Carpetas con `$` son predefinidas (usadas para gestión y mantenimiento).

### enum4linux
- Herramienta para enumerar usuarios a través de SMB en el puerto 445.

### snmpwalk
- Lista dispositivos en una red mediante el protocolo SNMP (puertos UDP 161 y 162).

### arp-scan
- Alternativa a `snmpwalk`, útil para detectar dispositivos en la red sin depender de puertos.

### nbtscan
- Lista equipos en la red a través de NetBIOS (puerto TCP 139).

## Codificación y Decodificación

### Decodificar Base64
```bash
echo "Qm9iIC0gIVBAJCRXMHJEITEyMw" | base64 --decode
```
Resultado:
```
Bob - !P@$sW0rD!123
```

## Protocolos Importantes

- **LDAP**: Utilizado por Active Directory para comunicación entre equipos.
- **NetBIOS**: Protocolo de Windows para comunicación en red, ahora reemplazado en gran parte por SMB.

## Tabla de Contenidos
- [Clase del 30-10-2024](#clase-del-30-10-2024)
- [Clase del 31-10-2024 - Cómo Evadir un Firewall](#clase-del-31-10-2024---cómo-evadir-un-firewall)
- [Herramientas para la Enumeración de Redes y Sistemas](#herramientas-para-la-enumeración-de-redes-y-sistemas)
- [Codificación y Decodificación](#codificación-y-decodificación)
- [Protocolos Importantes](#protocolos-importantes)


Hacking – Post-Explotación

• WinPEAS
• LinPEAS
• Gtfobins
• Lolbas
• Bashark
• Mimikatz
• Empire
• Msfvenom

Técnicas de evasión de Firewalls con NMAP
Cuando se realizan pruebas de penetración, uno de los mayores desafíos es evadir la detección de los Firewalls, que son diseñados para proteger las redes y sistemas de posibles amenazas. Para superar este obstáculo, Nmap ofrece una variedad de técnicas de evasión que permiten a los profesionales de seguridad realizar escaneos sigilosos y evitar así la detección de los mismos.
Algunos de estos parametros son:
•
MTU (--mtu): La técnica de evasión de MTU o “Maximum Transmission Unit” implica ajustar el tamaño de los paquetes que se envían para evitar la detección por parte del Firewall. Nmap permite configurar manualmente el tamaño máximo de los paquetes para garantizar que sean lo suficientemente pequeños para pasar por el Firewall sin ser detectados.
•
Data Length (--data-length): Esta técnica se basa en ajustar la longitud de los datos enviados para que sean lo suficientemente cortos como para pasar por el Firewall sin ser detectados. Nmap permite a los usuarios configurar manualmente la longitud de los datos enviados para que sean lo suficientemente pequeños para evadir la detección del Firewall.
•
Source Port (--source-port): Esta técnica consiste en configurar manualmente el número de puerto de origen de los paquetes enviados para evitar la detección por parte del Firewall. Nmap permite a los usuarios especificar manualmente un puerto de origen aleatorio o un puerto específico para evadir la detección del Firewall.
•
Decoy (-D): Esta técnica de evasión en Nmap permite al usuario enviar paquetes falsos a la red para confundir a los sistemas de detección de intrusos y evitar la detección del Firewall. El comando -D permite al usuario enviar paquetes falsos junto con los paquetes reales de escaneo para ocultar su actividad.
•
Fragmented (-f): Esta técnica se basa en fragmentar los paquetes enviados para que el Firewall no pueda reconocer el tráfico como un escaneo. La opción -f en Nmap permite fragmentar los paquetes y enviarlos por separado para evitar la detección del Firewall.
•
Spoof-Mac (--spoof-mac): Esta técnica de evasión se basa en cambiar la dirección MAC del paquete para evitar la detección del Firewall. Nmap permite al usuario configurar manualmente la dirección MAC para evitar ser detectado por el Firewall.
•
Stealth Scan (-sS): Esta técnica es una de las más utilizadas para realizar escaneos sigilosos y evitar la detección del Firewall. El comando -sS permite a los usuarios realizar un escaneo de tipo SYN sin establecer una conexión completa, lo que permite evitar la detección del Firewall.
•
min-rate (--min-rate): Esta técnica permite al usuario controlar la velocidad de los paquetes enviados para evitar la detección del Firewall. El comando --min-rate permite al usuario reducir la velocidad de los paquetes enviados para evitar ser detectado por el Firewall.
Es importante destacar que, además de las técnicas de evasión mencionadas anteriormente, existen muchas otras opciones en Nmap que pueden ser utilizadas para realizar pruebas de penetración efectivas y evadir la detección del Firewall. Sin embargo, las técnicas que hemos mencionado son algunas de las más populares y ampliamente utilizadas por los profesionales de seguridad para superar los obstáculos que presentan los Firewalls en la realización de pruebas de penetración.
