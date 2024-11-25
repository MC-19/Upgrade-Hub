
# Vulnerabilities in Cybersecurity

A **vulnerability** is a weakness or flaw in the design, implementation, or behavior of a system or application. Attackers can exploit these weaknesses to gain unauthorized access or perform unauthorized actions.

## NIST Definition
NIST defines a vulnerability as:
> "Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source."

Vulnerabilities can arise from poor design or oversight of user actions.

## Main Categories of Vulnerabilities

| Vulnerability Type         | Description                                                                                       |
|-----------------------------|---------------------------------------------------------------------------------------------------|
| **Operating System**        | Found within operating systems and often lead to privilege escalation.                           |
| **(Mis)Configuration-based**| Stem from incorrectly configured applications or services (e.g., a website exposing customer data). |
| **Weak or Default Credentials** | Default credentials (e.g., username/password as "admin") are easy to guess by attackers.        |
| **Application Logic**       | Poorly designed applications (e.g., weak authentication mechanisms) allow attackers to impersonate users. |
| **Human-Factor**            | Exploit human behavior, such as phishing emails tricking users into believing they are legitimate.|

As a cybersecurity researcher, understanding how to discover and exploit vulnerabilities is a crucial skill.


# Vulnerability Management and Scoring

**Vulnerability Management** is the process of evaluating, categorizing, and remediating threats faced by an organization. It focuses on addressing the most critical vulnerabilities to reduce the likelihood of attacks.

> **Fact**: Only about 2% of vulnerabilities are exploited (Kenna Security, 2020).

## Importance of Vulnerability Scoring
Vulnerability scoring helps assess the potential risk and impact of vulnerabilities. Popular frameworks include:

### Common Vulnerability Scoring System (CVSS)
- Introduced in 2005, now at version 3.1 (version 4.0 in draft).
- Factors:
  1. Ease of exploitation.
  2. Availability of exploits.
  3. Impact on the CIA triad (Confidentiality, Integrity, Availability).

#### CVSS Severity Scale:
| Rating      | Score         |
|-------------|---------------|
| **None**    | 0             |
| **Low**     | 0.1 - 3.9     |
| **Medium**  | 4.0 - 6.9     |
| **High**    | 7.0 - 8.9     |
| **Critical**| 9.0 - 10.0    |

#### Advantages and Disadvantages:
| **Advantages**                                   | **Disadvantages**                                                                 |
|--------------------------------------------------|-----------------------------------------------------------------------------------|
| Widely adopted and long-established.             | Not designed for prioritization, only severity assessment.                       |
| Free and recommended by NIST.                    | Scores rarely update with new exploit developments.                              |
| Popular in organizations.                        | Relies heavily on exploit availability (only 20% of vulnerabilities have exploits).|

---

### Vulnerability Priority Rating (VPR)
- Developed by Tenable as a **risk-driven** framework.
- Focuses on the **relevancy** of vulnerabilities to an organization.
- Scoring is dynamic, changing as vulnerabilities age.

#### VPR Severity Scale:
| Rating      | Score         |
|-------------|---------------|
| **Low**     | 0.0 - 3.9     |
| **Medium**  | 4.0 - 6.9     |
| **High**    | 7.0 - 8.9     |
| **Critical**| 9.0 - 10.0    |

#### Advantages and Disadvantages:
| **Advantages**                                 | **Disadvantages**                                                                 |
|------------------------------------------------|-----------------------------------------------------------------------------------|
| Real-world, modern framework.                  | Not open-source, tied to commercial platforms.                                   |
| Considers over 150 risk factors.               | CIA triad considerations are limited.                                           |
| Scores dynamically update over time.           |                                                                                   |

**Key Takeaway:** CVSS is severity-focused and widely adopted, while VPR is risk-focused and dynamic.



# Vulnerability Databases: NVD and Exploit-DB

In cybersecurity, applications and services often have different designs and behaviors, leading to unique vulnerabilities. Thankfully, resources exist to track these vulnerabilities for software, operating systems, and more.

## Key Terms
| Term               | Definition                                                                 |
|--------------------|---------------------------------------------------------------------------|
| **Vulnerability**  | A weakness or flaw in the design, implementation, or behavior of a system.|
| **Exploit**        | An action or behavior that utilizes a vulnerability.                      |
| **Proof of Concept (PoC)** | A technique or tool demonstrating the exploitation of a vulnerability. |

---

## National Vulnerability Database (NVD)
- Lists all publicly categorized vulnerabilities as **Common Vulnerabilities and Exposures (CVEs)**.
- CVEs are formatted as **CVE-YEAR-IDNUMBER** (e.g., CVE-2017-0144 used by WannaCry).
- Features:
  - Tracks confirmed CVEs.
  - Allows filtering by category and submission date.
  - Example: 223 new CVEs submitted within the first three days of August.

### Limitations:
- Not ideal for searching vulnerabilities specific to an application or scenario.

---

## Exploit-DB
- A hacker-focused resource retaining exploits for software and applications.
- Stores exploits categorized by:
  - Software name.
  - Author.
  - Version.
- Provides snippets of code (**Proof of Concepts**) for exploiting specific vulnerabilities.
- More practical for assessments compared to NVD.

---

**Key Takeaway:** Use **NVD** for tracking CVEs and general information, while **Exploit-DB** is ideal for actionable exploits and PoCs for specific software.



# Demonstrating Vulnerability Exploitation Process

In cybersecurity assessments, combining multiple vulnerabilities often leads to better results. This task demonstrates how to leverage a minor vulnerability to discover and exploit a more valuable one.

## Example Process: Using Version Disclosure
1. **Version Disclosure**:
   - Applications often display their version number for support or unintentionally.
   - Example: An application reveals its name and version as **"Apache Tomcat 9.0.17"**.

2. **Research Using Exploit-DB**:
   - With the version information in hand, use **Exploit-DB** to search for relevant exploits.
   - For **Apache Tomcat 9.0.17**, the search may yield **five potential exploits**.

---

## Key Insights:
- Combining vulnerabilities is a common practice for effective assessments.
- Version information is a valuable starting point for identifying exploitable vulnerabilities.
- **Exploit-DB** is an essential tool for finding and leveraging specific exploits.

---

**Takeaway**: Always start by identifying minor vulnerabilities, such as version disclosure, and use them to uncover more significant exploitation opportunities.

