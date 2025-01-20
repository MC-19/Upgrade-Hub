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

Privilege Escalation: Kernel Exploits

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

---
