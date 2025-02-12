# Metodologías de Pentesting

## PTES (Penetration Testing Execution Standard)
Un estándar diseñado para proporcionar un marco común en la ejecución de pruebas de penetración. Define metodologías y procedimientos detallados para realizar auditorías técnicas de seguridad tanto en empresas como en proveedores de servicios.

## OWASP (Open Web Application Security Project)
Organización sin ánimo de lucro dedicada a mejorar la seguridad de las aplicaciones web. Ofrece metodologías, guías y herramientas de seguridad, destacando el OWASP Top 10, un ranking de las vulnerabilidades más críticas en aplicaciones web.

## OSSTM (Open Source Security Testing Methodology Manual)
Manual que proporciona un marco de trabajo detallado para la ejecución de auditorías de seguridad. Describe las fases y técnicas a seguir en un pentesting completo.

## MITRE ATT&CK
Marco de referencia que documenta tácticas, técnicas y procedimientos utilizados por atacantes en escenarios reales. Se utiliza en equipos de Red Team y Blue Team para entender, mitigar y simular amenazas.

---

# Hacking – Conceptos Técnicos Previos

- **Target**: Objetivo (sistema, máquina, empresa, web…) que será evaluado o atacado.
- **CTF (Capture The Flag)**: Competición de seguridad informática donde los participantes deben explotar vulnerabilidades en sistemas para obtener *flags* que demuestran el acceso.
- **Alcance**: Nivel de profundidad con el que se ejecuta una auditoría de seguridad.
- **VPN (Virtual Private Network)**: Red privada virtual que crea un túnel seguro entre dos puntos sobre internet.
- **Vulnerabilidad**: Punto débil en un sistema que puede ser explotado por un atacante.
- **Exploit**: Código diseñado para aprovechar una vulnerabilidad y permitir la ejecución de acciones en el sistema.
- **Payload**: Código que ejecuta una acción maliciosa tras la explotación de una vulnerabilidad.
- **0-Day**: Vulnerabilidad no conocida por el proveedor o sin un parche disponible, lo que permite a los atacantes explotarla sin restricciones.

---

# Recolección de Información / Reconocimiento

## OSINT (Open Source Intelligence)
Técnicas y herramientas utilizadas para obtener información pública de un objetivo.

- **Google Dorks**: Uso de operadores avanzados de búsqueda en Google para encontrar información sensible.
- **[Shodan](https://www.shodan.io/)**: Motor de búsqueda de dispositivos conectados a internet.
- **[Robtex](https://www.robtex.com/)**: Herramienta de análisis de redes y dominios.
- **[DNSDumpster](https://dnsdumpster.com/)**: Servicio de recolección de información DNS y mapeo de infraestructura.
- **[Nslookup](https://www.nslookup.io/)**: Comando para realizar consultas DNS.
- **[Dig](https://toolbox.googleapps.com/apps/dig/)**: Herramienta avanzada para consultas DNS.
- **[Maltego](https://www.maltego.com/)**: Plataforma de análisis de relaciones y visualización de datos para OSINT.
- **[The Harvester](https://www.osintux.org/documentacion/the-harvester)**: Herramienta para recopilar correos electrónicos, subdominios e información de servidores mediante OSINT.
- **[Censys](https://search.censys.io/)**: Motor de búsqueda de activos en internet similar a Shodan.
- **[Hunter.io](https://hunter.io/)**: Servicio para encontrar direcciones de correo electrónico asociadas a un dominio.
- **[Phonebook.cz](https://phonebook.cz/)**: Herramienta OSINT para recopilar información sobre dominios y direcciones de correo.
- **[Verify Email Address](https://www.verifyemailaddress.org/)**: Servicio para validar la existencia de direcciones de correo electrónico.

---

## Enumeración / Escaneo
Proceso de identificación de servicios, puertos y usuarios en el sistema objetivo.

- **Ping**: Comprobación de disponibilidad de un host en la red.
- **arp-scan**: Escaneo de direcciones MAC en la red.
- **Nmap**: Escaneo de red y detección de servicios.
  - Uso de *scripts NSE* para identificar vulnerabilidades y servicios.
  - Técnicas de *firewall evasion* para saltar restricciones de seguridad.
  - Escaneo de *RDP* para detectar servicios de escritorio remoto.
- **Netdiscover**: Descubrimiento de dispositivos en una red local.
- **Smbclient**: Cliente SMB para interactuar con recursos compartidos en redes Windows.
- **Nbtscan**: Escaneo de redes para obtener información sobre NetBIOS.
- **Enum4Linux**: Herramienta para enumerar usuarios y recursos en sistemas Windows vía SMB.
- **AutoRecon**: Script de automatización de escaneos con Nmap y otras herramientas ([Repositorio en GitHub](https://github.com/Tib3rius/AutoRecon)).

---

# Nmap Cheatsheet

## Nmap - Trace the Packets
```bash
nmap --traceroute 192.168.1.1
```

## Connect Scan
```bash
nmap -sT 192.168.1.1
```

## Filtered Ports
```bash
nmap -p 22,80,443 --open 192.168.1.1
```

## Discovering Open UDP Ports
```bash
nmap -sU -p- 192.168.1.1
```

## Version Scan
```bash
nmap -sV 192.168.1.1
```

## Saving the Results
```bash
nmap -oN output.txt 192.168.1.1
nmap -oX output.xml 192.168.1.1
```

## Service Version Detection
```bash
nmap -sV 192.168.1.1
```

## Banner Grabbing
```bash
nmap -sV --script=banner 192.168.1.1
```

## Tcpdump
```bash
tcpdump -i eth0
```

## Nc (Netcat)
```bash
nc -zv 192.168.1.1 22-443
```

## Tcpdump - Intercepted Traffic
```bash
tcpdump -i eth0 port 80
```

## Nmap Scripting Engine
```bash
nmap --script=vuln 192.168.1.1
```

## Specific Scripts Category
```bash
nmap --script=auth 192.168.1.1
```

## Nmap - Specifying Scripts
```bash
nmap --script=http-title 192.168.1.1
```

## Nmap - Aggressive Scan
```bash
nmap -A 192.168.1.1
```

## Nmap - Vuln Category
```bash
nmap --script=vulners 192.168.1.1
```

## Timing and Optimization
```bash
nmap -T4 192.168.1.1
nmap --max-retries 2 192.168.1.1
```

## SYN-Scan
```bash
nmap -sS 192.168.1.1
```

## ACK-Scan
```bash
nmap -sA 192.168.1.1
```

## Detect IDS/IPS
```bash
nmap -sS --scan-delay 500ms 192.168.1.1
```

## Decoys
```bash
nmap -D RND:10 192.168.1.1
```

## Scan by Using Decoys
```bash
nmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1
```

## Testing Firewall Rule
```bash
nmap -p 80 --badsum 192.168.1.1
```

## Scan by Using Different Source IP
```bash
nmap --source-port 53 192.168.1.1
```

## DNS Proxying
```bash
nmap --dns-servers 8.8.8.8 192.168.1.1
```

## SYN-Scan of a Filtered Port
```bash
nmap -sS -p 443 192.168.1.1
```

## SYN-Scan From DNS Port
```bash
nmap -sS --source-port 53 192.168.1.1
```

## Connect To The Filtered Port
```bash
nmap -sT -p 443 192.168.1.1
```










