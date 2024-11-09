
# Hack The Box - Network Enumeration with Nmap

## Introduction

Enumeration is a vital phase in penetration testing, focused not only on accessing a target system but on discovering all possible attack vectors. Here are key aspects:

1. **Purpose of Enumeration**: Identify and understand attack paths by gathering detailed information on services and configurations.
2. **Tool Limitations**: Automated tools like Nmap are valuable but have constraints, such as timeouts that may miss open ports.
3. **Manual Enumeration**: Direct interaction with services often reveals critical information missed by automated scans.
4. **Configuration Issues**: Many vulnerabilities arise from misconfigurations and poor security practices, providing easy entry points.
5. **Interpreting Tool Results**: Adjusting and actively interpreting tool outputs prevents overlooking hidden details.
6. **Knowledge over Tools**: True success in enumeration comes from knowledge and analysis, beyond the tools used.

With these principles, enumeration becomes the foundation for effective penetration testing, enabling you to recognize and exploit potential vulnerabilities confidently.


# Introduction to Nmap

**Network Mapper (Nmap)** is an open-source tool for network analysis and security auditing, primarily used to:
- Identify available hosts on a network.
- Detect services and applications (including versions) running on hosts.
- Determine operating systems and configurations, such as firewalls or IDS settings.

## Use Cases
Nmap is widely used by network administrators and IT security professionals for:
- Security audits and vulnerability assessments.
- Penetration test simulations.
- Firewall and IDS verification.
- Network mapping and response analysis.
- Identifying open ports.

## Nmap Architecture
Nmap supports various scan types, each designed for specific tasks:
- **Host Discovery**: Finds active devices on the network.
- **Port Scanning**: Determines which ports are open.
- **Service Enumeration and Detection**: Identifies services and their versions.
- **OS Detection**: Determines the target’s operating system.
- **Nmap Scripting Engine (NSE)**: Allows custom interaction with services.

## Basic Syntax
The basic Nmap syntax is:
```bash
nmap <scan types> <options> <target>
```

## Scan Techniques
Nmap provides numerous scan techniques to suit different reconnaissance needs. Common scans include:
- **TCP SYN scan (-sS)**: Quickly scans thousands of ports without completing the full TCP handshake.
- **TCP Connect scan (-sT)**: Completes the full TCP handshake.
- **UDP scan (-sU)**: Probes open UDP ports.
- **Null, FIN, and Xmas scans (-sN, -sF, -sX)**: Evasion scans that send packets with unusual flags.
- **Idle scan (-sI)**: Uses a "zombie" host to hide the origin of the scan.
- **SCTP scan (-sY)**: Scans for SCTP services.

**Example of a TCP SYN Scan**:
```bash
sudo nmap -sS localhost
```
This command performs a SYN scan on the localhost. Ports respond as follows:
- **SYN-ACK**: Indicates the port is open.
- **RST**: Indicates the port is closed.
- **No response**: Marked as filtered, possibly due to firewall rules.

### Example Output
```bash
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5432/tcp open  postgresql
5901/tcp open  vnc-1
```
In this output, we see open TCP ports along with their corresponding services.

---


# Host Discovery with Nmap

**Host Discovery** is essential in internal penetration testing, especially when scanning a network to identify active systems. Nmap provides several options to determine if a target is online, with ICMP echo requests being one of the most effective methods.

## Recommended Practices
- Store each scan's results for documentation and comparison, as different tools may yield different outcomes.

## Key Host Discovery Techniques

1. **Scan a Network Range**:
   ```bash
   sudo nmap 10.129.2.0/24 -sn -oA tnet
   ```
   - `-sn`: Disables port scanning, focusing on host discovery.
   - `-oA tnet`: Saves output in multiple formats.

2. **Scan from an IP List**:
   Use a predefined list of IP addresses to check which hosts are active.
   ```bash
   sudo nmap -sn -oA tnet -iL hosts.lst
   ```
   - `-iL hosts.lst`: Scans targets from a file (hosts.lst).

3. **Scan Multiple IPs or a Range**:
   Scanning specific IPs or ranges is also possible by listing them directly or using a range.
   ```bash
   sudo nmap -sn -oA tnet 10.129.2.18-20
   ```

4. **Scan a Single IP**:
   For individual hosts, check if the target is online before conducting a full port scan.
   ```bash
   sudo nmap 10.129.2.18 -sn -oA host
   ```

## Advanced Options
- **ICMP Echo Requests (-PE)**: Ensures Nmap sends ICMP pings.
- **Packet Trace (--packet-trace)**: Shows all packets sent and received for detailed analysis.
- **Reason (--reason)**: Displays why Nmap identified a host as alive.
- **Disable ARP Ping (--disable-arp-ping)**: Avoids ARP requests to focus on ICMP.

**Example**:
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```
This command performs a detailed ICMP ping scan while disabling ARP requests, useful when the ARP ping is not required or interferes with results.

---

