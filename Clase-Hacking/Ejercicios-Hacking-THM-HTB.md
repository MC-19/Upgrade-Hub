
# Ejercicio 1: TryHackMe - Passive Reconnaissance

## Introducción

En este ejercicio, aprenderemos a usar **whois**, **nslookup** y **dig**, así como otros conceptos relacionados.

- **whois** se utiliza para realizar consultas sobre registros WHOIS.
- **nslookup** y **dig** se emplean para consultar registros de bases de datos DNS.

Además, conoceremos **DNSDumpster** y **Shodan.io**, servicios en línea que permiten recopilar información sobre un objetivo sin interactuar directamente con él.

## Reconocimiento Pasivo versus Activo

- **Reconocimiento Pasivo**: Confía en información pública disponible sin necesidad de interactuar con el objetivo. Actividades comunes incluyen:
  - Consultar los registros DNS de un dominio a través de un servidor DNS público.
  - Revisar ofertas de trabajo publicadas en el sitio web de la empresa.
  - Leer artículos o informes sobre la empresa.

- **Reconocimiento Activo**: Implica contacto directo con el objetivo, lo cual puede revelar la actividad del analista. Ejemplos incluyen:
  - Conectarse a servidores del objetivo (por ejemplo, HTTP, FTP o SMTP).
  - Llamar a la empresa para solicitar información.
  - Acceder físicamente a la empresa haciéndose pasar por personal de mantenimiento.

## Whois

**WHOIS** es un protocolo de solicitud y respuesta que sigue el estándar [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt). Un servidor WHOIS escucha en el puerto 43 TCP para recibir peticiones. Los registradores de dominio son responsables de mantener los registros de los nombres de dominio que administran. Los datos clave que proporcionan los servidores WHOIS incluyen:

  - **Registrador**: ¿A través de qué registrador se registró el nombre de dominio?
  - **Información de contacto del registrante**: Nombre, organización, dirección, teléfono y otros detalles (a menos que estén ocultos mediante un servicio de privacidad).
  - **Fechas de creación, actualización y expiración**: ¿Cuándo se registró el nombre de dominio por primera vez? ¿Cuándo fue actualizado por última vez? ¿Y cuándo necesita ser renovado?
  - **Servidor de nombres**: ¿Qué servidor se debe consultar para resolver el nombre de dominio?

## nslookup y dig

**nslookup** y **dig** son herramientas para consultar registros DNS y obtener información detallada sobre un dominio.

### Parámetros de nslookup

1. **OPTIONS**: Especifica el tipo de consulta, por ejemplo:
   - `A`: Devuelve direcciones IPv4.
   - `AAAA`: Devuelve direcciones IPv6.
   - `CNAME`: Nombre canónico.
   - `MX`: Servidores de correo.
   - `SOA`: Inicio de autoridad.
   - `TXT`: Registros de texto.

2. **DOMAIN_NAME**: Dominio que se desea consultar.

3. **SERVER**: Servidor DNS para realizar la consulta. Ejemplos de servidores DNS públicos incluyen:
   - Cloudflare: `1.1.1.1`, `1.0.0.1`
   - Google: `8.8.8.8`, `8.8.4.4`
   - Quad9: `9.9.9.9`, `149.112.112.112`

**Ejemplo de nslookup**:
```bash
nslookup -type=A tryhackme.com 1.1.1.1
```
Este comando devolverá las direcciones IPv4 asociadas al dominio `tryhackme.com`.

### dig

- **dig** (Domain Information Groper) es otra herramienta avanzada para consultas DNS.
- Para especificar el tipo de registro, se utiliza el formato `dig DOMAIN_NAME TYPE`.

**Ejemplo de dig**:
```bash
dig @1.1.1.1 tryhackme.com MX
```
**Comparación**: A diferencia de `nslookup`, `dig` proporciona más detalles por defecto, como el TTL (Time To Live) de cada registro.

---

