# Internet Search Engine Operators

## Introduction
Search engines like Google, Bing, and DuckDuckGo offer advanced operators to refine searches effectively.

## Common Google Search Operators
1. **Exact Phrase**:
   - Use `" "` to find pages with the exact word or phrase.
   - Example: `"passive reconnaissance"`

2. **Site Search**:
   - Use `site:` to limit searches to a specific domain.
   - Example: `site:tryhackme.com success stories`

3. **Exclude Words**:
   - Use `-` to exclude specific words or phrases from results.
   - Example: `pyramids -tourism`

4. **File Type Search**:
   - Use `filetype:` to find files of specific formats like PDF, DOC, XLS, or PPT.
   - Example: `filetype:ppt cyber security`

## Additional Resources
- Explore more advanced operators on your preferred search engine.

## Note
These operators are a great starting point for advanced searches. Tailor them to suit your needs.


# Specialized Search Engines

## Shodan
- **Purpose**: Search for Internet-connected devices (servers, IoT, industrial systems).
- **Example**: Search `apache 2.4.1` to find servers running this version.
- **Features**:
  - Trends: Historical insights (subscription required).
  - Query Examples: Visit [Shodan Search Query Examples](https://www.shodan.io).

## Censys
- **Purpose**: Focuses on Internet-connected hosts, websites, certificates, and assets.
- **Use Cases**:
  - Enumerating domains.
  - Auditing open ports/services.
  - Discovering rogue assets.
- **Details**: Visit [Censys Search Use Cases](https://censys.io).

## VirusTotal
- **Purpose**: Online file and URL scanning using multiple antivirus engines.
- **Features**:
  - Upload files or input URLs to scan.
  - Check file hashes for previous results.
  - Community comments for deeper insights.
- **Note**: False positives may occur; rely on community feedback for clarity.

## Have I Been Pwned (HIBP)
- **Purpose**: Check if an email address has appeared in leaked data breaches.
- **Importance**:
  - Indicates leaked private information and passwords.
  - Highlights risks of password reuse across platforms.
- **Details**: Visit [Have I Been Pwned](https://haveibeenpwned.com).

## Notes on Images
- Visual results like those shown on the websites provide additional context. Refer to the platforms for detailed screenshots and examples.


# Common Vulnerabilities and Exploitures (CVE) and Exploit Resources

## Common Vulnerabilities and Exposures (CVE)
- **Definition**: CVE is a dictionary of standardized identifiers for software and hardware vulnerabilities.
- **Format**: Each vulnerability is assigned a unique ID, e.g., `CVE-2024-29988`.
- **Purpose**:
  - Standardization ensures all parties (researchers, vendors, IT professionals) refer to the same vulnerability.
  - Example: `CVE-2014-0160` (Heartbleed).
- **Maintained By**: The MITRE Corporation.
- **Resources**:
  - [CVE Program Website](https://cve.mitre.org)
  - [National Vulnerability Database (NVD)](https://nvd.nist.gov)

## Exploit Database
- **Purpose**: A repository of exploit codes for known vulnerabilities.
- **Use Case**:
  - Assessing company security as part of red teaming (with proper permission and legal agreements).
- **Features**:
  - Lists exploit codes from various authors.
  - Some exploits are tested and marked as verified.
- **Resource**:
  - [Exploit Database](https://www.exploit-db.com)

## GitHub
- **Purpose**: A platform where you can find tools related to CVEs, including:
  - Proof-of-Concept (PoC) codes.
  - Exploit codes.
- **Use Case**:
  - Search GitHub for specific vulnerabilities (e.g., Heartbleed).

## Notes on Images
- Visuals such as screenshots of CVE entries or exploit searches provide additional insights. Visit the respective platforms for detailed examples.


# Official Documentation

## Importance of Official Documentation
Official documentation provides accurate, reliable, and up-to-date information about commands, tools, or products. It is a vital resource for understanding features and functionality.

---

## Examples of Official Documentation

### 1. **Linux Manual Pages (man pages)**
- **Purpose**: Provides help for Linux/Unix-like system commands, system calls, library functions, and configuration files.
- **Usage**:
  - Use the `man` command followed by the command name.
  - Example: `man ip` displays the manual page for the `ip` command.
  - Press `q` to quit the manual page.
- **Access Online**:
  - Search `man ip` in any search engine to access the page via a web browser.
- **Tip**:
  - Use platforms like the **AttackBox** to run Linux commands directly in your browser.

---

### 2. **Microsoft Windows Technical Documentation**
- **Purpose**: Official resource for Windows commands and tools.
- **Example**:
  - Searching for `ipconfig` on the [Microsoft Technical Documentation](https://docs.microsoft.com) website provides details about the command's usage and options.

---

### 3. **Product Documentation**
- **Purpose**: Organized manuals for popular products, offering detailed insights into their features and functionality.
- **Examples**:
  - **Snort**: [Snort Official Documentation](https://www.snort.org/documents)
  - **Apache HTTP Server**: [Apache Documentation](https://httpd.apache.org/docs/)
  - **PHP**: [PHP Documentation](https://www.php.net/docs.php)
  - **Node.js**: [Node.js Documentation](https://nodejs.org/en/docs/)

---

## Why Use Official Documentation?
- **Up-to-Date**: Contains the latest information about tools and products.
- **Complete**: Comprehensive resource for learning and troubleshooting.
- **Reliable**: Trusted by developers and users alike.

## Notes on Images
- Visual examples, like manual pages or search results, can be accessed directly on respective platforms for more context.
