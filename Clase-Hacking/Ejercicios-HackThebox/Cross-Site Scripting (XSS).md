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
