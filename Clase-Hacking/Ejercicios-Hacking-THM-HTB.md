Ejercicio 1 TryHackMe <-> Passive Reconnaissance

# Intro:

Aprenderemos whois, nslookup y dig mas todo lo relacionado.

who is se usa para las query WHOIS records, mientars que nslookup y dig para las query de base de datos records.

Aparte aprenderemos DNSDumpster y Shodan.io que son servicios en lineaque nos dejan recopilar informacion sobre el objetivo sin conectarnos directamente a el.

# Passive Versus Active Recon:

El reconocimiento pasivo, confias en el conocimiento publico. Es el conocimiento al que puedes acceder por fuentes publicas sin interqactuar con el target.
  Incluye muchas actividades como:
    - Ver los DNS records del dominio por un servidor DNS publico.
    - Buscar propuestas de trabajo del sitio web.
    - leyendo articulos sobre el target de la compañia.

El reconocimiento activo, por el otro lado, no p se puede lograr tan discretamente. Necesitas contacto directo con el target. Como si fueras a forzar una cerradura.
  Ejemplos de esta actividad son:
    - Conectarse a uno de los servidores como HTTP, FTP o SMTP.
    - Llamar a la compañia para obtener informacion.
    - Entrando a la compañia haciendose pasar como un reparador.

· Whois

WHOIS es un protocolo de solicitud y respuesta que sigue al [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt). Un servidor WHOIS escucha por TCP al servidor 43 por peticiones entrantes. El dominio registrar es responsable de mantener registros de los nombres de dominio que está arrendando.
Los servidores de WHOIS responden varia informacion relacionada con el dominio preguntado, los intereses particulares son:
  - Registrar: A través de qué registrador se registró el nombre de dominio?
  - Contact info of registrant: Nombre, organización, dirección, teléfono y otros detalles (a menos que estén ocultos mediante un servicio de privacidad).
  - Creation, update, and expiration dates: Cuándo se registró el nombre de dominio por primera vez? ¿Cuándo fue actualizado por última vez? ¿Y cuándo necesita ser renovado?
  - Name Server: ¿Qué servidor se debe consultar para resolver el nombre de dominio?

# nslookup and dig

nslookup y dig son herramientas para consultar registros DNS y obtener información detallada sobre un dominio.
  Parámetros de nslookup
    -1 OPTIONS: Tipo de consulta, por ejemplo:
      - A: Devuelve direcciones IPv4.
      - AAAA: Devuelve direcciones IPv6.
      - CNAME: Nombre canónico.
      - MX: Servidores de correo.
      - SOA: Inicio de autoridad.
      - TXT: Registros de texto.
    -2 DOMAIN_NAME: Dominio que se quiere consultar.
    -3 SERVER: Servidor DNS a usar para la consulta. Ejemplos de servidores DNS públicos incluyen:
      - Cloudflare: 1.1.1.1, 1.0.0.1
      - Google: 8.8.8.8, 8.8.4.4
      - Quad9: 9.9.9.9, 149.112.112.112
      
Ejemplo
```
nslookup -type=A tryhackme.com 1.1.1.1
```
Este comando devolverá las direcciones IPv4 asociadas al dominio tryhackme.com.

dig
  - dig (Domain Information Groper) es otra herramienta avanzada para consultas DNS.
  - Para especificar el tipo de registro, se utiliza dig DOMAIN_NAME TYPE. Ejemplo

Ejemplo
```
dig @1.1.1.1 tryhackme.com MX
```
Comparación: A diferencia de nslookup, dig proporciona más detalles por defecto, como el TTL (Time To Live) de cada registro.







