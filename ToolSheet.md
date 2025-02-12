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

Este documento proporciona una base sólida para el pentesting. Si quieres añadir más herramientas o afinar la información en algún aspecto, dime y lo ajustamos.
