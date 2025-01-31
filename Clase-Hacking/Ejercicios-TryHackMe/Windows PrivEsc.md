# Windows Privilege Escalation Room

This room is aimed at walking you through a variety of Windows Privilege Escalation techniques. To do this, you must first deploy an intentionally vulnerable Windows VM. This VM was created by Sagi Shahar as part of his local privilege escalation workshop but has been updated by Tib3rius as part of his *Windows Privilege Escalation for OSCP and Beyond!* course on Udemy. Full explanations of the various techniques used in this room are available there, along with demos and tips for finding privilege escalations in Windows.

## Prerequisites

Make sure you are connected to the TryHackMe VPN or using the in-browser Kali instance before trying to access the Windows VM!

## Connecting to the Windows VM

RDP should be available on port **3389** (it may take a few minutes for the service to start). You can log in to the **user** account using the following credentials:

```bash
xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.135.112
```

## Privilege Escalation Techniques

The next tasks will walk you through different privilege escalation techniques. After each technique, you should obtain an **admin** or **SYSTEM** shell. Remember to exit out of the shell and/or re-establish a session as the **user** account before starting the next task!
