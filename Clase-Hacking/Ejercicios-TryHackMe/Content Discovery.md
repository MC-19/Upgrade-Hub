# Content Discovery in Web Application Security

## What is Content in Web Application Security?

In the context of web application security, **content** refers to various elements such as files, videos, pictures, backups, or website features. While some content is obvious and intended for public access, other content might be hidden or not meant to be accessible publicly. 

### Examples of Hidden Content
- Staff-only pages or portals
- Older versions of the website
- Backup files
- Configuration files
- Administration panels

---

## Methods of Content Discovery

There are three primary methods for discovering hidden content on a website:

1. **Manual Discovery**: Using browser-based tools and exploring the application manually to identify non-visible content.
2. **Automated Discovery**: Leveraging tools to automate the process of finding hidden files, directories, or endpoints.
3. **OSINT (Open-Source Intelligence)**: Gathering publicly available information to identify potential hidden content or vulnerabilities.

---

## Getting Started

To begin practicing content discovery:
1. Start the **AttackBox** by clicking the blue "Start AttackBox" button.
2. Access the machine provided for this task and follow the exercises.

---

By mastering these methods, you'll develop a deeper understanding of how to identify and secure hidden content in web applications.

# Content Discovery: Robots.txt

## What is Robots.txt?

The `robots.txt` file is a document used by websites to communicate with search engine crawlers. It specifies which parts of the website are allowed or disallowed for indexing by search engines. While its primary purpose is to guide search engines, this file can also unintentionally reveal sensitive or hidden areas of a website.

### Why is Robots.txt Important in Security?

As penetration testers, the `robots.txt` file can be a valuable resource. It often contains paths to restricted or private areas of the website that site owners prefer to keep hidden, such as:
- Administration portals
- Customer-only areas
- Backup files or directories

These paths may inadvertently highlight potential targets for further investigation.

---

## Example: Acme IT Support Robots.txt

To explore the `robots.txt` file for the Acme IT Support website:

1. Open **Firefox** on the **AttackBox**.
2. Navigate to the URL: `http://10.10.62.33/robots.txt`.
   - Note: This URL will refresh 2 minutes after starting the machine in Task 1.

Review the file for any disallowed directories or paths that might contain interesting content or hidden functionality.

---

## Key Takeaways

- The `robots.txt` file is a guide for search engines but can unintentionally reveal sensitive areas of a website.
- Use the information found in `robots.txt` to identify potential targets for further security testing.
- Always review this file as part of your manual content discovery process.

Start analyzing `robots.txt` files to uncover hidden opportunities for penetration testing!

# Content Discovery: Favicon

## What is a Favicon?

A **favicon** is a small icon displayed in the browser's address bar or tab to represent a website's branding. However, when a framework is used to build a website, the default favicon included with the framework might be left in place. This can provide valuable information about the framework or technologies used to build the website.

---

## Why Does the Favicon Matter in Security?

Identifying a framework through its favicon can reveal:
- The underlying technologies or framework stack in use.
- Potential vulnerabilities or misconfigurations if the framework version is outdated.

### OWASP Favicon Database
OWASP hosts a database of common framework icons that can be used to identify frameworks through their favicon. Visit [OWASP Favicon Database](https://wiki.owasp.org/index.php/OWASP_favicon_database) to look up favicon hashes and correlate them with frameworks.

---

## Practical Exercise: Identifying a Favicon

### Steps:
1. Open **Firefox** on the **AttackBox**.
2. Navigate to: `https://static-labs.tryhackme.cloud/sites/favicon/`.
   - The website displays a placeholder message: "Website coming soon..."
   - Look at the browser tab to notice the favicon icon.

3. **View the Page Source**:
   - Locate line 6, which contains a link to the favicon file: `images/favicon.ico`.

4. **Download and Hash the Favicon**:
   - Run the following command on the AttackBox:
     ```bash
     curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
     ```
   - Note: Free users on the AttackBox may encounter issues with `curl`. Use an external VM or follow the Windows instructions below if needed.

5. **Windows PowerShell Instructions**:
   - Download the favicon file:
     ```powershell
     PS C:\> curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico -UseBasicParsing -o favicon.ico
     ```
   - Generate the MD5 hash:
     ```powershell
     PS C:\> Get-FileHash .\favicon.ico -Algorithm MD5
     ```

6. **Lookup the Hash**:
   - Use the MD5 hash generated to search in the [OWASP Favicon Database](https://wiki.owasp.org/index.php/OWASP_favicon_database).

---

## Key Takeaways

- Favicons can reveal information about a website's framework or underlying technologies.
- Use tools like `curl` or PowerShell to download and hash the favicon for identification.
- Utilize the OWASP Favicon Database to correlate hashes with frameworks and further your research.

Identifying the framework can give you insights into potential vulnerabilities and guide your penetration testing efforts.

# Content Discovery: Sitemap.xml

## What is a Sitemap.xml?

The `sitemap.xml` file is an XML document used to provide search engines with a structured list of all the pages and files that the website owner wants to be indexed. Unlike `robots.txt`, which restricts crawlers, the `sitemap.xml` actively guides them to specific parts of the site.

---

## Why is Sitemap.xml Important in Security?

For penetration testers, the `sitemap.xml` can be a goldmine of information as it may include:
- Hard-to-navigate sections of the website.
- Deprecated or old pages still accessible behind the scenes.
- Hidden areas not linked directly on the website.

These areas could potentially expose vulnerabilities or sensitive data.

---

## Practical Exercise: Exploring Sitemap.xml

### Steps:
1. **Access the Sitemap**:
   - Open **Firefox** on the **AttackBox**.
   - Navigate to: `http://10.10.62.33/sitemap.xml`.

2. **Analyze the Contents**:
   - Review the list of pages and directories included in the sitemap.
   - Identify any new or previously undiscovered content that may warrant further investigation.

---

## Key Takeaways

- The `sitemap.xml` file can reveal hidden or hard-to-find pages.
- Old or deprecated pages listed in the sitemap may still be accessible and pose security risks.
- Always include the `sitemap.xml` file in your manual content discovery workflow.

Utilize the insights from `sitemap.xml` to uncover potential targets and expand your understanding of the website's structure.

# Content Discovery: HTTP Headers

## What Are HTTP Headers?

HTTP headers are metadata sent by the web server as part of its response to a client request. These headers can provide important information, such as:
- **Webserver software** (e.g., NGINX, Apache).
- **Programming/scripting language** in use (e.g., PHP, Python).
- Security-related configurations or additional metadata.

For penetration testers, HTTP headers can help identify technologies and their versions, which might lead to the discovery of vulnerabilities.

---

## Example: HTTP Headers in a Response

When making a request to a web server, the headers returned might look like this:

```plaintext
*   Trying 10.10.62.33:80...
* TCP_NODELAY set
* Connected to 10.10.62.33 (10.10.62.33) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.62.33
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< X-Powered-By: PHP/7.4.3
< Date: Mon, 19 Jul 2021 14:39:09 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
```

# Content Discovery: Framework Stack

## What is a Framework Stack?

A **framework stack** refers to the software and technologies used to build and run a website. Identifying the framework can reveal valuable insights, including:
- Potential vulnerabilities in the framework.
- Hidden directories or features tied to the framework.
- Administrative portals or deprecated functionalities.

---

## How to Identify a Framework Stack

### Methods:
1. **Favicon Clues**:
   - Some frameworks come with default favicons that developers may leave unchanged.
   - Use tools like the [OWASP Favicon Database](https://wiki.owasp.org/index.php/OWASP_favicon_database) to identify frameworks based on their favicons.

2. **Page Source**:
   - Look for comments, copyright notices, or credits that reference the framework.
   - Examine any linked resources or scripts that might indicate the framework in use.

---

## Practical Exercise: Identifying the Framework on Acme IT Support

### Steps:
1. **View the Page Source**:
   - Open the **AttackBox** browser and navigate to: `http://10.10.62.33`.
   - Scroll to the bottom of the page. You'll see a comment containing:
     - Page load time.
     - A link to the framework's website: `https://static-labs.tryhackme.cloud/sites/thm-web-framework`.

2. **Visit the Framework Website**:
   - Open `https://static-labs.tryhackme.cloud/sites/thm-web-framework`.
   - Navigate to the **Documentation** page.
   - The documentation reveals the path to the framework's **administration portal**.

3. **Access the Administration Portal**:
   - Use the discovered path to access the portal on the Acme IT Support website.
   - Viewing this portal will reveal a **flag**.

---

## Key Takeaways

- Identifying the framework stack provides valuable insights into the technologies and structure of a website.
- Framework documentation can reveal hidden paths, such as administration portals.
- Always inspect the page source and linked resources for clues about the framework in use.

By leveraging the framework's information, you can expand your understanding of the target and discover potential vulnerabilities or hidden content.

# External Resources for Content Discovery: OSINT

## What is OSINT?

**OSINT (Open-Source Intelligence)** refers to freely available tools and resources that gather information about a target website or system. These tools are invaluable for penetration testers looking to discover hidden content or information about their target.

---

## Google Hacking / Dorking

**Google hacking**, also known as **dorking**, utilizes Google's advanced search features to filter and refine search results. This method allows you to uncover specific information about a target website by combining filters and keywords.

### Common Google Search Filters

| **Filter**   | **Example**                   | **Description**                                             |
|--------------|-------------------------------|-------------------------------------------------------------|
| `site`       | `site:tryhackme.com`          | Returns results only from the specified website address.    |
| `inurl`      | `inurl:admin`                 | Returns results with the specified word in the URL.         |
| `filetype`   | `filetype:pdf`                | Returns results that are a specific file type or extension. |
| `intitle`    | `intitle:admin`               | Returns results with the specified word in the title.       |

You can combine these filters for more precise results. For example:
```plaintext
site:tryhackme.com inurl:admin filetype:pdf
```

# Content Discovery: Wappalyzer

## What is Wappalyzer?

**Wappalyzer** is an online tool and browser extension designed to identify the technologies used by a website. It can uncover information about:
- Frameworks
- Content Management Systems (CMS)
- Payment processors
- Analytics tools
- Programming languages
- Server technologies
- Version numbers (if available)

---

## Why Use Wappalyzer?

For penetration testers, understanding the technologies behind a website provides valuable context for:
- Identifying potential vulnerabilities.
- Tailoring testing strategies based on the detected stack.
- Uncovering outdated or unsupported versions of technologies.

---

## How to Use Wappalyzer

### 1. **Online Tool**:
   - Visit [Wappalyzer](https://www.wappalyzer.com/).
   - Enter the URL of the target website to analyze its technology stack.

### 2. **Browser Extension**:
   - Install the Wappalyzer extension for your preferred browser.
   - Navigate to the target website, and the extension will display its findings in real-time.

---

## Practical Application

Using Wappalyzer, you can:
1. Identify frameworks or CMS in use (e.g., WordPress, Django).
2. Detect server-side technologies (e.g., NGINX, Apache).
3. Uncover analytics or tracking tools (e.g., Google Analytics).
4. Look for version numbers to determine if the software is up to date.

---

## Key Takeaways

- **Wappalyzer** simplifies the process of identifying a website's technologies.
- It provides a comprehensive overview of frameworks, CMS, and server-side tools.
- Use this information to enhance your penetration testing and vulnerability discovery process.

Start exploring websites with Wappalyzer to gain insights into their technology stack!

# Content Discovery: Wayback Machine

## What is the Wayback Machine?

The **Wayback Machine** (https://archive.org/web/) is a historical archive of websites that dates back to the late 1990s. It allows you to view snapshots of websites as they appeared at various points in time.

---

## Why Use the Wayback Machine in Security?

For penetration testers, the Wayback Machine can help uncover:
- **Old pages** or directories that may still exist on the current website.
- **Deprecated functionalities** or unprotected endpoints.
- **Exposed content**, such as credentials or sensitive data, that may have been removed but is still accessible in archived snapshots.

---

## How to Use the Wayback Machine

### Steps:
1. Visit [Wayback Machine](https://archive.org/web/).
2. Enter the domain name of the target website (e.g., `example.com`).
3. Browse the timeline of snapshots to explore how the website looked at different points in time.

---

## Practical Applications

### Use Cases:
1. **Discover Legacy Pages**:
   - Identify pages that have been removed but may still be active on the server.
2. **Gather Insights**:
   - Observe changes in the website's structure, content, or functionality over time.
3. **Identify Potential Exposures**:
   - Look for sensitive information that was inadvertently included in earlier versions of the site.

---

## Key Takeaways

- The Wayback Machine provides valuable historical insights into a website's structure and content.
- Archived snapshots can help uncover hidden or forgotten vulnerabilities.
- Always include the Wayback Machine in your OSINT (Open-Source Intelligence) toolkit for a comprehensive analysis.

Start exploring your target's historical data with the Wayback Machine today!

# Content Discovery: GitHub

## What is GitHub?

**GitHub** is a web-based platform for hosting and sharing projects that use **Git**, a version control system. Git tracks changes to files in a project, making collaboration easier for teams by allowing users to:
- See edits and changes made by team members.
- Commit changes with messages for clarity.
- Push changes to a central repository for others to pull.

On GitHub, repositories can be:
- **Public**: Accessible to everyone on the internet.
- **Private**: Restricted to authorized users with specific access controls.

---

## Why Use GitHub in Penetration Testing?

GitHub can provide penetration testers with valuable information, such as:
- **Source code** of the target's application.
- **Sensitive information**, like passwords or API keys.
- **Insights into development practices** and technologies in use.

By searching GitHub for repositories associated with your target, you may uncover content that was inadvertently exposed.

---

## How to Search GitHub for Content

### Steps:
1. Visit [GitHub](https://github.com/).
2. Use the search bar to look for:
   - **Company names** (e.g., `Acme IT Support`).
   - **Website domains** (e.g., `example.com`).
3. Refine your search with filters or advanced search operators like:
   - `filename:password`: Searches for files named "password".
   - `org:<organization_name>`: Searches within a specific organization.

---

## Practical Use Cases

### Discovering Public Repositories:
- Find repositories associated with the target's organization or website.

### Identifying Sensitive Information:
- Look for exposed API keys, credentials, or configuration files.

### Analyzing Source Code:
- Understand the technologies and frameworks used.
- Look for potential vulnerabilities in the code.

---

## Key Takeaways

- GitHub is a powerful tool for discovering sensitive information and insights about your target.
- Use advanced search techniques to locate relevant repositories.
- Public repositories may expose valuable data that complements other reconnaissance efforts.

Add GitHub to your OSINT (Open-Source Intelligence) arsenal to enhance your penetration testing workflow!

# Content Discovery: S3 Buckets

## What Are S3 Buckets?

**S3 Buckets** are a cloud storage service provided by Amazon AWS. They allow users to store files and static website content accessible over HTTP and HTTPS. File access permissions can be configured to:
- **Public**: Files are accessible by anyone.
- **Private**: Files are restricted to authorized users.
- **Writable**: Files can be modified or uploaded by authorized users.

However, misconfigurations in access permissions may expose files that should not be publicly accessible, creating potential security risks.

---

## S3 Bucket URL Format

S3 bucket URLs follow the format:
```plaintext
http(s)://{name}.s3.amazonaws.com
```

# Automated Discovery

## What is Automated Discovery?

**Automated discovery** is the process of using tools to uncover content on a website, such as hidden files or directories, by sending numerous requests to the web server. Unlike manual discovery, this process automates the task and can perform hundreds, thousands, or even millions of requests in a short amount of time.

Automated discovery relies on **wordlists**, which contain common directory and file names, to systematically check for the existence of resources on a website.

---

## What Are Wordlists?

**Wordlists** are text files containing a list of commonly used words for specific purposes. In the context of content discovery, wordlists include:
- Common directory names (e.g., `admin`, `backup`, `login`).
- Common file names (e.g., `config.php`, `index.html`).

### Example Resource for Wordlists:
[SecLists](https://github.com/danielmiessler/SecLists) is an extensive collection of wordlists curated by Daniel Miessler. It is preinstalled on the **TryHackMe AttackBox** and includes wordlists for:
- Web content discovery
- Passwords
- DNS
- Vulnerabilities

---

## Automation Tools

### Commonly Used Tools for Content Discovery:
1. **ffuf (Fuzz Faster U Fool)**:
   - A fast and flexible tool for brute-forcing directories and files.
   - Command:
     ```bash
     ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.62.33/FUZZ
     ```

2. **dirb**:
   - A simple yet effective tool for brute-forcing web content.
   - Command:
     ```bash
     dirb http://10.10.62.33/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
     ```

3. **gobuster**:
   - A fast, multi-threaded tool for directory and file brute-forcing.
   - Command:
     ```bash
     gobuster dir --url http://10.10.62.33/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
     ```

---

## Practical Exercise

### Steps:
1. Open the **AttackBox** terminal.
2. Run the provided commands for `ffuf`, `dirb`, and `gobuster`.
3. Analyze the results to identify discovered directories and files on the target website (`http://10.10.62.33`).

---

## Key Takeaways

- **Automated discovery** significantly accelerates the process of uncovering hidden content on a website.
- Tools like `ffuf`, `dirb`, and `gobuster` utilize **wordlists** to systematically check for resources.
- Use results from automated tools to identify potential entry points or sensitive files.

Leverage these tools to uncover valuable insights and expand your penetration testing workflow.
