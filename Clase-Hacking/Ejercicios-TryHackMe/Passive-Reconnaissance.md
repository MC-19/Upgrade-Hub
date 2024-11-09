
# Exercise 1: TryHackMe - Passive Reconnaissance

## Introduction

In this exercise, we will learn how to use **whois**, **nslookup**, and **dig**, along with related concepts.

- **whois** is used to perform WHOIS record queries.
- **nslookup** and **dig** are used to perform DNS database record queries.

We will also explore **DNSDumpster** and **Shodan.io**, which are online services that allow gathering information about a target without directly connecting to it.

## Passive vs. Active Reconnaissance

- **Passive Reconnaissance**: Relies on publicly available information without interacting directly with the target. Common activities include:
  - Checking DNS records of a domain using a public DNS server.
  - Reviewing job postings published on the target company's website.
  - Reading articles or reports about the target company.

- **Active Reconnaissance**: Requires direct interaction with the target, which can reveal the analyst's activity. Examples include:
  - Connecting to the target's servers (e.g., HTTP, FTP, SMTP).
  - Calling the company to request information.
  - Physically entering the company pretending to be maintenance staff.

## Whois

**WHOIS** is a request and response protocol following [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt). A WHOIS server listens on TCP port 43 for incoming requests. Domain registrars are responsible for maintaining records of the domain names they manage. Key information provided by WHOIS servers includes:

  - **Registrar**: Which registrar was the domain name registered through?
  - **Registrant Contact Info**: Name, organization, address, phone, and other details (unless hidden by a privacy service).
  - **Creation, Update, and Expiration Dates**: When was the domain first registered? When was it last updated? When does it need to be renewed?
  - **Name Server**: Which server should be consulted to resolve the domain name?

## nslookup and dig

**nslookup** and **dig** are tools used to query DNS records and gather detailed information about a domain.

### nslookup Parameters

1. **OPTIONS**: Specifies the query type, for example:
   - `A`: Returns IPv4 addresses.
   - `AAAA`: Returns IPv6 addresses.
   - `CNAME`: Canonical name.
   - `MX`: Mail servers.
   - `SOA`: Start of authority.
   - `TXT`: Text records.

2. **DOMAIN_NAME**: Domain name to be queried.

3. **SERVER**: DNS server to be used for the query. Examples of public DNS servers include:
   - Cloudflare: `1.1.1.1`, `1.0.0.1`
   - Google: `8.8.8.8`, `8.8.4.4`
   - Quad9: `9.9.9.9`, `149.112.112.112`

**Example of nslookup**:
```bash
nslookup -type=A tryhackme.com 1.1.1.1
```
This command will return the IPv4 addresses associated with the domain `tryhackme.com`.

### dig

- **dig** (Domain Information Groper) is another advanced tool for DNS queries.
- To specify the record type, use `dig DOMAIN_NAME TYPE`.

**Example of dig**:
```bash
dig @1.1.1.1 tryhackme.com MX
```
**Comparison**: Unlike `nslookup`, `dig` provides more details by default, such as the TTL (Time To Live) of each record.

## DNSDumpster

**DNSDumpster** is an online tool useful for discovering subdomains and getting a detailed view of DNS records without needing to perform manual DNS queries.

- **Subdomains**: Unlike tools like `nslookup` and `dig`, DNSDumpster can reveal hidden subdomains that might contain valuable information, such as outdated or vulnerable services.
- **Complete Query**: With a single search in DNSDumpster, you can obtain:
  - Subdomains and their IP addresses.
  - Complete DNS records (A, MX, TXT, etc.).
  - Geographical location of servers.
- **Graphical Visualization**: DNSDumpster organizes results into tables and generates a visual graph showing how DNS and MX records connect to their respective servers.

This tool allows exporting the graph and rearranging elements, making it easier to visually identify the target's infrastructure.

## Shodan.io

**Shodan.io** is a search engine designed to identify devices connected to the internet rather than web pages, making it useful for both penetration testing and security defenses.

- **Collected Information**: Shodan scans and records information about accessible devices online. This includes:
  - IP address
  - Hosting provider
  - Geographical location
  - Server type and version
- **Use in Passive Reconnaissance**: By searching a domain or IP address on Shodan.io, you can obtain a complete view of associated devices without directly interacting with them.
- **Defensive Functionality**: Organizations can use Shodan.io to monitor their connected and exposed devices on the network, helping to identify potential vulnerabilities.

**Example**: Searching for `tryhackme.com` on Shodan.io provides detailed records of its servers and other connected devices.

---

This guide provides an introduction to essential tools for **passive reconnaissance**, helping you obtain DNS and device information without direct interaction with the target.
