
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


