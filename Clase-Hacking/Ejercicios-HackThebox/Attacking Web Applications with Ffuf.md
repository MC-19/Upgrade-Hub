# Attacking Web Applications with Ffuf

Welcome to the **Attacking Web Applications with Ffuf** module!

There are many tools and methods to utilize for directory and parameter fuzzing/brute-forcing. In this module, we will mainly focus on the `ffuf` tool for web fuzzing, as it is one of the most common and reliable tools available for web fuzzing.

## Topics Covered

1. **Fuzzing for directories**
2. **Fuzzing for files and extensions**
3. **Identifying hidden vhosts**
4. **Fuzzing for PHP parameters**
5. **Fuzzing for parameter values**

## Overview

Tools such as `ffuf` provide us with a handy automated way to fuzz the web application's individual components or a web page. This means, for example, that we use a list to send requests to the webserver to check if a page with a name from our list exists on the server. If we get a response code `200`, then we know that this page exists on the webserver, and we can inspect it manually.

---

## Web Fuzzing

We will start by learning the basics of using `ffuf` to fuzz websites for directories. We run the exercise in the question below, visit the URL it provides, and observe the following website:

```
http://SERVER_IP:PORT
```

The website has no links to anything else, nor does it give us any information that can lead us to more pages. So, it looks like our only option is to 'fuzz' the website.

### Fuzzing

The term fuzzing refers to a testing technique that sends various types of user input to a certain interface to study how it reacts. For example:

- **Fuzzing for SQL injection vulnerabilities** involves sending random special characters and observing how the server responds.
- **Fuzzing for buffer overflows** involves sending increasingly long strings to see if and when the binary breaks.

For web fuzzing, we usually utilize pre-defined wordlists of commonly used terms for each type of test. Web servers do not usually provide a directory of all available links and domains (unless terribly configured), so we must check for various links and see which ones return pages. For example:

- Visiting `https://www.hackthebox.eu/doesnotexist` would result in an HTTP 404 Page Not Found error.
- Visiting `https://www.hackthebox.eu/login` would display the login page and return an HTTP 200 OK response.

This is the basic idea behind web fuzzing for pages and directories. However, doing this manually is impractical due to the time it would take. Automated tools like `ffuf` can:

- Send hundreds of requests per second.
- Analyze the HTTP response codes.
- Determine whether pages exist or not.

Thus, we can quickly identify existing pages and manually examine their content.

### Wordlists

To determine which pages exist, we use a wordlist containing commonly used words for web directories and pages, similar to a Password Dictionary Attack (covered later in the module). While this won't reveal all pages (e.g., those with random or unique names), it can uncover the majority of pages, achieving up to 90% success on some websites.

Thankfully, we don't need to create these wordlists from scratch. The GitHub **SecLists** repository offers a vast collection of pre-made wordlists for various types of fuzzing, including web directories and passwords. In our PwnBox environment, the SecLists repository is available under:

```
/opt/useful/SecLists
```

For this module, we will use the commonly used wordlist `directory-list-2.3-small.txt`, which can be located as follows:

```
DJMC@htb[/htb]$ locate directory-list-2.3-small.txt
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

---

## Directory Fuzzing

Now that we understand the concept of Web Fuzzing and know our wordlist, we are ready to start using `ffuf` to find website directories.

### Ffuf

`Ffuf` is pre-installed on your PwnBox instance. If you want to use it on your own machine, you can either use:

```
apt install ffuf -y
```

or download it and use it from its GitHub repository. As a new user of this tool, we will start by issuing the `ffuf -h` command to see how the tool can be used:

```
DJMC@htb[/htb]$ ffuf -h

HTTP OPTIONS:
  -H               Header "Name: Value", separated by colon. Multiple -H flags are accepted.
  -X               HTTP method to use (default: GET)
  -b               Cookie data "NAME1=VALUE1; NAME2=VALUE2" for copy as curl functionality.
  -d               POST data
  -recursion       Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth Maximum recursion depth. (default: 0)
  -u               Target URL
...SNIP...

MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ms              Match HTTP response size
...SNIP...

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
...SNIP...

INPUT OPTIONS:
...SNIP...
  -w               Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -o               Write output to file
...SNIP...

EXAMPLE USAGE:
  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
  Colored, verbose output.
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
...SNIP...
```

As we can see, the help output is quite large, so we only kept the options that may become relevant for us in this module.

### Performing Directory Fuzzing

From the example above, the two main options we use are `-w` for wordlists and `-u` for the URL. We can assign a wordlist to a keyword to refer to it during fuzzing. For example:

```
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```

To fuzz for web directories, we place the `FUZZ` keyword where the directory would be in our URL, like this:

```
DJMC@htb[/htb]$ ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ
```

Running the final command on our target:

```
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

<SNIP>
blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

We see that `ffuf` tested for almost 90k URLs in less than 10 seconds. This speed may vary depending on your internet speed and ping, but it should still be extremely fast.

You can increase the speed by raising the number of threads (e.g., `-t 200`), but this is not recommended for remote sites as it may cause disruptions, denial of service, or even bring down your internet connection in severe cases. 

We get some hits and can visit one of them to verify its existence:

```
http://SERVER_IP:PORT/blog
```

We get an empty page, indicating that the directory does not have a dedicated page but shows that we do have access to it, as we do not get an HTTP 404 Not Found or 403 Access Denied.

In the next section, we will look for pages under this directory to see whether it is really empty or has hidden files and pages.

---

## Page Fuzzing

We now understand the basic use of `ffuf` through the utilization of wordlists and keywords. Next, we will learn how to locate pages.

> **Note**: We can spawn the same target from the previous section for this section's examples as well.

### Extension Fuzzing

In the previous section, we found that we had access to `/blog`, but the directory returned an empty page, and we cannot manually locate any links or pages. So, we will once again utilize web fuzzing to see if the directory contains any hidden pages. However, before we start, we must find out what types of pages the website uses, like `.html`, `.aspx`, `.php`, or something else.

One common way to identify that is by finding the server type through the HTTP response headers and guessing the extension. For example, if the server is Apache, then it may be `.php`, or if it was IIS, then it could be `.asp` or `.aspx`, and so on. This method is not very practical, though. So, we will again utilize `ffuf` to fuzz the extension, similar to how we fuzzed for directories. Instead of placing the `FUZZ` keyword where the directory name would be, we would place it where the extension would be `.FUZZ`, and use a wordlist for common extensions. We can utilize the following wordlist in SecLists for extensions:

```
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ <SNIP>
```

Before we start fuzzing, we must specify which file that extension would be at the end of! We can always use two wordlists and have a unique keyword for each, and then do `FUZZ_1.FUZZ_2` to fuzz for both. However, there is one file we can always find in most websites, which is `index.*`, so we will use it as our file and fuzz extensions on it.

> **Note**: The wordlist we chose already contains a dot (`.`), so we will not have to add the dot after `index` in our fuzzing.

Now, we can rerun our command, carefully placing our `FUZZ` keyword where the extension would be after `index`:

```
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/indexFUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 5
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
:: Progress: [39/39] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

We do get a couple of hits, but only `.php` gives us a response with code `200`. Great! We now know that this website runs on PHP to start fuzzing for PHP files.

### Page Fuzzing

We will now use the same concept of keywords we've been using with `ffuf`, use `.php` as the extension, place our `FUZZ` keyword where the filename should be, and use the same wordlist we used for fuzzing directories:

```
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/FUZZ.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
REDACTED                [Status: 200, Size: 465, Words: 42, Lines: 15]
:: Progress: [87651/87651] :: Job [1/1] :: 5843 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

We get a couple of hits; both have an HTTP code `200`, meaning we can access them. `index.php` has a size of 0, indicating that it is an empty page, while the other does not, which means that it has content. We can visit any of these pages to verify this.

---

# Recursive Fuzzing

Recursive fuzzing automates the process of fuzzing directories and their subdirectories, enabling more efficient exploration of complex website structures. This is especially useful for websites with extensive directory trees, such as `/login/user/content/uploads/...`.

## Recursive Flags

Recursive scanning ensures that newly identified directories are automatically scanned for additional content until the entire website and its subdirectories are fuzzed. However, this can become time-consuming with deep directory trees. To optimize the process:

- **Set a Depth Limit:** Use a depth value to restrict the scan to a specific level, such as direct subdirectories only.
- **Selective Rescans:** After the initial scan, focus on the most interesting directories for a more targeted approach.

## Using Recursive Flags in ffuf

### Key Flags

- `-recursion`: Enables recursive scanning.
- `-recursion-depth [value]`: Sets the maximum depth for recursion.
- `-e .php`: Specifies the file extension to search for.
- `-v`: Outputs full URLs for clarity.

### Example Command
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
     -u http://SERVER_IP:PORT/FUZZ \
     -recursion \
     -recursion-depth 1 \
     -e .php \
     -v
```

### Output Example
```text
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/
    * FUZZ: 

[INFO] Adding a new job to the queue: http://SERVER_IP:PORT/forum/FUZZ
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/index.php
    * FUZZ: index.php

[Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://SERVER_IP:PORT/blog | --> | http://SERVER_IP:PORT/blog/
    * FUZZ: blog

[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/index.php
    * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/
    * FUZZ: 
```

### Notes

- Recursive fuzzing significantly increases the number of requests sent and the overall scan duration.
- Wordlists are applied twice: once with the specified file extension (e.g., `.php`) and once without.

### Summary
With recursive fuzzing, we can efficiently map out a website's structure while maintaining control over scan depth and focusing on the most relevant results. Adding the `-v` flag ensures clarity by displaying the full URLs for identified directories and files.

---

# DNS Records

When accessing the page under `/blog`, we encountered a message stating that the Admin panel has moved to `academy.htb`. However, visiting the URL directly in the browser results in the following error:

```
Can’t connect to the server at www.academy.htb
```

### Understanding the Issue

The exercises in HTB are local websites, not public ones. Browsers require URLs to be mapped to IPs, which they attempt to resolve by:

1. Checking the local `/etc/hosts` file.
2. Querying the public DNS (e.g., Google’s DNS `8.8.8.8`).

If the URL isn’t found in either, the browser cannot connect. Visiting the IP directly works because the browser bypasses the need for name resolution.

### Adding the Domain to `/etc/hosts`

To resolve `academy.htb`, we need to add it to our `/etc/hosts` file manually. Use the following command:

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

Now, you can visit the website by appending the port number to the URL:

```
http://academy.htb:PORT
```

### Verifying the Domain

After adding the entry, visiting the URL shows the same website as when accessing the IP directly. For example, accessing `/blog/index.php` confirms that `academy.htb` is mapped correctly to the same target.

### Verifying the Domain

After adding the entry, visiting the URL shows the same website as when accessing the IP directly. For example, accessing `/blog/index.php` confirms that `academy.htb` is mapped correctly to the same target.

### Exploring Subdomains

Since recursive scans on the target IP didn’t reveal anything related to `admin` or `panels`, the next step involves searching for subdomains under `*.academy.htb` to identify additional resources.

## Sub-domain Fuzzing

Sub-domain fuzzing allows us to identify subdomains (e.g., `*.website.com`) for any given website.

### What is a Sub-domain?

A sub-domain is any underlying website associated with a primary domain. For example, `https://photos.google.com` is the `photos` sub-domain of `google.com`.

### Pre-requisites

Before starting a scan, ensure you have the following:

1. **A Wordlist:** Sub-domain wordlists can be found in the SecLists repository under `/opt/useful/seclists/Discovery/DNS/`. For this example, we’ll use `subdomains-top1million-5000.txt`.
2. **A Target:** For demonstration purposes, we’ll use `inlanefreight.com`.

### Fuzzing Command

Using `ffuf`, place the `FUZZ` keyword in the subdomain position and execute the scan:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

#### Example Output

```text
[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www
```

### Scanning Academy.htb

To scan `academy.htb`, use the following command:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```

#### Example Output

```text
:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```

### Analysis

If no results are returned, it does not mean there are no subdomains. Instead, it indicates that there are no **public sub-domains** under `academy.htb`, as it lacks a public DNS record. Adding `academy.htb` to `/etc/hosts` only resolves the main domain; it does not assist in finding subdomains, as `ffuf` queries public DNS records during sub-domain fuzzing.

---

## Vhost Fuzzing

Vhost fuzzing allows us to identify virtual hosts (VHosts) that may not have public DNS records or belong to non-public websites. This is done by testing HTTP headers.

### VHosts vs. Sub-domains

The key difference between VHosts and sub-domains is:

- **VHosts:** Sub-domains served on the same server and sharing the same IP.
- **Sub-domains:** May or may not share the same server or IP.

### Why Use Vhost Fuzzing?

Sub-domains without public DNS records cannot be detected using traditional sub-domain fuzzing. By targeting the `Host` header during an HTTP request, Vhost fuzzing identifies both public and private sub-domains served from the same IP.

### Fuzzing Command

Using `ffuf`, place the `FUZZ` keyword in the `Host` header as follows:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

#### Example Output

```text
mail2                   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2                    [Status: 200, Size: 900, Words: 423, Lines: 56]
ns3                     [Status: 200, Size: 900, Words: 423, Lines: 56]
dns1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
lists                   [Status: 200, Size: 900, Words: 423, Lines: 56]
webmail                 [Status: 200, Size: 900, Words: 423, Lines: 56]
static                  [Status: 200, Size: 900, Words: 423, Lines: 56]
web                     [Status: 200, Size: 900, Words: 423, Lines: 56]
www1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
```

### Analysis

In the above example, all entries return `200 OK`. This behavior is expected because the `Host` header is modified during each request, and the server responds as if accessing the main site. However, if a valid VHost is specified, the response size or content will differ, indicating a new or distinct virtual host.

---


# Filtering Results

So far, we have not been using any filtering with `ffuf`, and the results are automatically filtered by default by their HTTP code, which filters out code `404 NOT FOUND`, and keeps the rest. However, as we saw in our previous run of `ffuf`, we can get many responses with code `200`. So, in this case, we will have to filter the results based on another factor, which we will learn in this section.

## Filtering

`ffuf` provides the option to match or filter out a specific HTTP code, response size, or amount of words. We can see that with `ffuf -h`:

```
Filtering Results
DJMC@htb[/htb]$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
<...SNIP...>
```

In this case, we cannot use matching, as we don't know what the response size from other VHosts would be. We know the response size of the incorrect results, which, as seen from the test above, is `900`, and we can filter it out with `-fs 900`. Now, let's repeat the same previous command, add the above flag, and see what we get:

```
Filtering Results
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900


       /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__/\ \ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb:PORT/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.academy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 900
________________________________________________

<...SNIP...>
admin                   [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [4997/4997] :: Job [1/1] :: 1249 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

We can verify that by visiting the page, and seeing if we can connect to it:

```
https://admin.academy.htb:PORT/
```

**Note 1**: Don't forget to add `admin.academy.htb` to `/etc/hosts`.

**Note 2**: If your exercise has been restarted, ensure you still have the correct port when visiting the website.

We see that we can access the page, but we get an empty page, unlike what we got with `academy.htb`, therefore confirming this is indeed a different VHost. We can even visit `https://admin.academy.htb:PORT/blog/index.php`, and we will see that we would get a `404 PAGE NOT FOUND`, confirming that we are now indeed on a different VHost.

Try running a recursive scan on `admin.academy.htb`, and see what pages you can identify.

---

# Parameter Fuzzing - POST

The main difference between POST requests and GET requests is that POST requests are not passed with the URL and cannot simply be appended after a `?` symbol. POST requests are passed in the data field within the HTTP request. Check out the Web Requests module to learn more about HTTP requests.

To fuzz the data field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send POST requests.

> **Tip**: In PHP, "POST" data "content-type" can only accept `application/x-www-form-urlencoded`. So, we can set that in `ffuf` with `-H 'Content-Type: application/x-www-form-urlencoded'`.

So, let us repeat what we did earlier, but place our `FUZZ` keyword after the `-d` flag:

```
  Parameter Fuzzing - POST
DJMC@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__/\ \ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=key
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

id                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
<...SNIP...>
```

As we can see this time, we got a couple of hits, the same one we got when fuzzing GET and another parameter, which is `id`. Let's see what we get if we send a POST request with the `id` parameter. We can do that with `curl`, as follows:

```
  Parameter Fuzzing - POST
DJMC@htb[/htb]$ curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```

As we can see, the message now says `Invalid id!`.

---

# Value Fuzzing

After fuzzing a working parameter, we now have to fuzz the correct value that would return the flag content we need. This section will discuss fuzzing for parameter values, which should be fairly similar to fuzzing for parameters, once we develop our wordlist.

## Custom Wordlist

When it comes to fuzzing parameter values, we may not always find a pre-made wordlist that would work for us, as each parameter would expect a certain type of value.

For some parameters, like usernames, we can find a pre-made wordlist for potential usernames, or we may create our own based on users that may potentially be using the website. For such cases, we can look for various wordlists under the SecLists directory and try to find one that may contain values matching the parameter we are targeting. In other cases, like custom parameters, we may have to develop our own wordlist. In this case, we can guess that the `id` parameter can accept a number input of some sort. These IDs can be in a custom format, or can be sequential, like from 1-1000 or 1-1000000, and so on. We'll start with a wordlist containing all numbers from 1-1000.

There are many ways to create this wordlist, from manually typing the IDs in a file, or scripting it using Bash or Python. The simplest way is to use the following command in Bash that writes all numbers from 1-1000 to a file:

```
  Value Fuzzing
DJMC@htb[/htb]$ for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Once we run our command, we should have our wordlist ready:

```
  Value Fuzzing
DJMC@htb[/htb]$ cat ids.txt

1
2
3
4
5
6
<...SNIP...>
```

Now we can move on to fuzzing for values.

## Value Fuzzing

Our command should be fairly similar to the POST command we used to fuzz for parameters, but our `FUZZ` keyword should be put where the parameter value would be, and we will use the `ids.txt` wordlist we just created, as follows:

```
  Value Fuzzing
DJMC@htb[/htb]$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__/\ \ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:30794/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

We see that we get a hit right away. We can finally send another POST request using `curl`, as we did in the previous section, use the `id` value we just found, and collect the flag.

---


# Skills Assessment - Web Fuzzing

## Ejercicio

### Sub-domain/Vhost Fuzzing Scan

#### Comando
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://94.237.62.184:32267/ -H 'Host: FUZZ.academy.htb' -fs 985
```

#### Sub-dominios identificados:
- archive.academy.htb
- faculty.academy.htb

---

### Extension Fuzzing Scan

#### Comando
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://archive.academy.htb:32267/indexFUZZ
```

#### Extensiones aceptadas:
- .php
- .html
- .txt

---

### Page Fuzzing Scan

#### Comando
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:33469/FUZZ -recursion -recursion-depth 1 -e .php,phps,php7 -v -t 80
```
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:33469/courses/FUZZ -recursion -recursion-depth 1 -e .php,phps,php7 -v -t 80
```

#### URL de la página que muestra "You don't have access!":
- http://faculty.academy.htb:33469/courses/linux-security.php7

---

### Parameter Discovery

#### Comando
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://faculty.academy.htb:33469/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'  -fs 774
```

#### Parámetros identificados:
- username
- password

---

### Parameter Fuzzing for Flag

#### Comando
```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:33469/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781
```
```bash
curl http://faculty.academy.htb:33469/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'
```

#### Contenido de la flag:
```
HTB{example_flag_content}
