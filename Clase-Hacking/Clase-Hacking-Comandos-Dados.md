
# Clase de Hacking

## Clase del 30-10-2024

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
