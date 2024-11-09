
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
   - `-oA tnet`: 	Stores the results in all formats starting with the name 'tnet'.

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

   ```bash
   sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
   ```
   - `-oA host`: Stores the results in all formats starting with the name 'host'.
   - `-PE`: Performs the ping scan by using 'ICMP Echo requests' against the target.
   - `--packet-trace`: Shows all packets sent and received.
  
   ```bash
   sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
   ```
   - `--reason`: Displays the reason for specific result.

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


# Host and Port Scanning with Nmap

Effective host and port scanning with Nmap provides a deeper understanding of a target's open ports, services, service versions, and even operating system details.

## Port States in Nmap
Nmap identifies six possible states for scanned ports:
- **open**: Connection established (TCP, UDP, or SCTP).
- **closed**: Connection rejected with an RST flag (useful to confirm if a host is alive).
- **filtered**: No response; Nmap cannot determine if the port is open or closed, likely due to firewall rules.
- **unfiltered**: Only seen in TCP-ACK scans; indicates accessibility but unclear if open or closed.
- **open|filtered**: No response; suggests firewall or packet filtering.
- **closed|filtered**: Specific to IP ID idle scans; port state cannot be confirmed as closed or filtered.

## Key Scanning Techniques

### 1. Scanning Top TCP Ports
Scan the most common ports for a target.
```bash
sudo nmap 10.129.2.28 --top-ports=10
```

### 2. Detailed SYN Scan with Packet Tracing
View packet exchange details for deeper insights.
```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

### 3. TCP Connect Scan (-sT)
Uses a full three-way handshake to identify open/closed ports (high accuracy, low stealth).
```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

### 4. Handling Filtered Ports
Observe firewall behavior on ports, such as TCP port 139 (filtered state).
```bash
sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn
```

### 5. Discovering Open UDP Ports
Since UDP does not use a handshake, it has a longer timeout and is slower to scan.
```bash
sudo nmap 10.129.2.28 -F -sU
```

#### Advanced UDP Scan Example
Enables packet tracing and specific port selection with UDP scanning.
```bash
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason
```

### 6. Version Detection (-sV)
Provides detailed information about open ports, including service versions.
```bash
sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason -sV
```

## Important Options Explained
- **-sn**: Disables port scanning for host discovery only.
- **-Pn**: Disables ICMP echo requests.
- **-n**: Disables DNS resolution.
- **--packet-trace**: Shows all packets sent and received.
- **-sS / -sT / -sU**: SYN scan, TCP connect scan, and UDP scan, respectively.
- **-sV**: Detects service versions.
- **-p <port(s)>**: Specifies individual ports or ranges to scan.
- **--top-ports**: Scans the most common ports.
- **--reason**: Shows reasons for the port state.
- **--disable-arp-ping**: Disables ARP requests, focusing on ICMP pings.

Ejercicio1:
   Find all TCP ports on your target. Submit the total number of found TCP ports as the answer.
      ```nmap -vv -sT -p 1-65535 10.129.92.172``` 

Ejercicio2
   Enumerate the hostname of your target and submit it as the answer. (case-sensitive)
      ```dsaadsad```
      
---




