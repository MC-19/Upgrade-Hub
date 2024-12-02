
# Introduction to Hashes and John the Ripper

## What are Hashes?
A **hash** is a way of taking a piece of data of any length and representing it in another fixed-length form. This process masks the original value of the data. The hash value is obtained by running the original data through a hashing algorithm. Many popular hashing algorithms exist, such as **MD4**, **MD5**, **SHA1**, and **NTLM**.

### Example:
- Input: `polo` (a string of 4 characters)
  - MD5 Hash: `b53759f3ce692de7aff1b5779d3964da`

- Input: `polomints` (a string of 9 characters)
  - MD5 Hash: `584b6e4f4586e136bc280f27f9c64f3b`

---

## What Makes Hashes Secure?
Hashing functions are designed as **one-way functions**. In other words, it is easy to calculate the hash value of a given input; however, it is a hard problem to find the original input given the hash value.

In computer science, the efficiency of algorithms can be classified as follows:

### P (Polynomial Time)
- Problems that can be solved in polynomial time. Example: Sorting a list in increasing order.

### NP (Non-deterministic Polynomial Time)
- Problems where a solution can be checked quickly but finding the solution itself might be hard.

Hashing is an example of a "P" problem for generating hashes but an "NP" problem for reversing them.

---

## Where John Comes In
Even though the algorithm is not feasibly reversible, cracking hashes is possible using dictionary attacks. If you know the hash and its algorithm, you can:
1. Hash a large number of words (dictionary).
2. Compare these hashes to the target hash.
3. If they match, the hash is cracked.

**John the Ripper** is a tool for conducting fast brute-force and dictionary attacks on various hash types.

---

## Learning More
For more in-depth material, consider exploring:
- [Cryptography Basics](#)
- [Public Key Cryptography Basics](#)
- [Hashing Basics](#)

This room focuses on the extended version of **John the Ripper**, commonly called **Jumbo John**.


# John the Ripper: Basic Syntax and Usage

## John Basic Syntax
The basic syntax of John the Ripper commands is as follows. We will cover the specific options and modifiers used as we use them.

```
john [options] [file path]
```

- `john`: Invokes the John the Ripper program.
- `[options]`: Specifies the options you want to use.
- `[file path]`: The file containing the hash you’re trying to crack; if it’s in the same directory, you won’t need to name a path, just the file.

---

## Automatic Cracking
John has built-in features to detect what type of hash it’s being given and to select appropriate rules and formats to crack it for you. To do this, use the following syntax:

```
john --wordlist=[path to wordlist] [path to file]
```

### Options:
- `--wordlist=`: Specifies using wordlist mode, reading from the file that you supply in the provided path.
- `[path to wordlist]`: The path to the wordlist you’re using, as described in the previous task.

**Example Usage**:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

---

## Identifying Hashes
Sometimes, John won’t play nicely with automatically recognising and loading hashes, but that’s okay! We can use tools to identify the hash type.

### Using `hash-identifier`:
A Python tool to identify hash types. To use it:
1. Download the `hash-id.py` file:
   ```
   wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
   ```
2. Run it:
   ```
   python3 hash-id.py
   ```

**Example Output**:
```
HASH: 2e728dd31fb5949bc39cac5a9f066498

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

---

## Format-Specific Cracking
Once you have identified the hash format, you can tell John to use it while cracking the hash:

```
john --format=[format] --wordlist=[path to wordlist] [path to file]
```

### Options:
- `--format=`: Specifies that you’re giving John a hash of a specific format.
- `[format]`: The format that the hash is in.

**Example Usage**:
```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

---

## Listing Available Formats
To check if you need to add the `raw-` prefix or not, list all formats supported by John:
```
john --list=formats
```
Or, use `grep` to search for your hash type:
```
john --list=formats | grep -iF "md5"
```



# Cracking NTLM Hashes with John the Ripper

## NTHash / NTLM

NTHash is the hash format modern Windows operating system machines use to store user and service passwords. It’s also commonly referred to as NTLM, which references the previous version of Windows format for hashing passwords known as LM, thus NT/LM.

### A bit of history

The NT designation for Windows products originally meant **New Technology**. It was used starting with Windows NT to denote products not built from the MS-DOS Operating System. Eventually, the “NT” line became the standard Operating System type to be released by Microsoft, and the name was dropped, but it still lives on in the names of some Microsoft technologies.

### How it works in Windows

In Windows, SAM (Security Account Manager) is used to store user account information, including usernames and hashed passwords. You can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, using a tool like **Mimikatz**, or using the Active Directory database: **NTDS.dit**. You may not have to crack the hash to continue privilege escalation, as you can often conduct a **“pass the hash” attack** instead, but sometimes, hash cracking is a viable option if there is a weak password policy.

---

## Practical Usage

Now that you know the theory behind it, use the techniques we practised in the previous tasks and the knowledge of NTLM hashes to crack the `ntlm.txt` file!

### Steps

1. **Ensure you have John the Ripper installed.**
   - Use the Jumbo John version for additional tools if needed.
   
2. **Identify the type of hash in the `ntlm.txt` file.**
   - Use tools like `hash-id` or `john --list=formats`.

3. **Use John to crack the hash.**
   - Command format:
     ```bash
     john --format=nt --wordlist=[path to wordlist] [path to hash file]
     ```
   - Example:
     ```bash
     john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ~/John-the-Ripper-The-Basics/Task05/ntlm.txt
     ```

4. **Check the results:**
   - Use:
     ```bash
     john --show [path to hash file]
     ```

---

## Notes
- NTLM hashes are relatively fast to crack, so weak passwords will be found quickly using a good wordlist like `rockyou.txt`.
- If John fails to identify the format automatically, explicitly specify `--format=nt` for NTLM hashes.



# Cracking Hashes from /etc/shadow

The `/etc/shadow` file is the file on Linux machines where password hashes are stored. It also stores other information, such as the date of the last password change and password expiration information. It contains one entry per line for each user or user account of the system. This file is usually only accessible by the root user, so you must have sufficient privileges to access the hashes. However, if you do, there is a chance that you will be able to crack some of the hashes.

## Unshadowing

John can be very particular about the formats it needs data in to be able to work with it; for this reason, to crack `/etc/shadow` passwords, you must combine it with the `/etc/passwd` file for John to understand the data it’s being given. To do this, we use a tool built into the John suite of tools called `unshadow`. The basic syntax of `unshadow` is as follows:

```bash
unshadow [path to passwd] [path to shadow]
```

- `unshadow`: Invokes the unshadow tool  
- `[path to passwd]`: The file that contains the copy of the `/etc/passwd` file you’ve taken from the target machine  
- `[path to shadow]`: The file that contains the copy of the `/etc/shadow` file you’ve taken from the target machine  

### Example Usage:

```bash
unshadow local_passwd local_shadow > unshadowed.txt
```

### Note on the Files

When using `unshadow`, you can either use the entire `/etc/passwd` and `/etc/shadow` files, assuming you have them available, or you can use the relevant line from each. For example:

**FILE 1 - `local_passwd`**

Contains the `/etc/passwd` line for the root user:

```bash
root:x:0:0::/root:/bin/bash
```

**FILE 2 - `local_shadow`**

Contains the `/etc/shadow` line for the root user:

```bash
root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::
```

## Cracking

We can then feed the output from `unshadow`, in our example use case called `unshadowed.txt`, directly into John. We should not need to specify a mode here as we have made the input specifically for John; however, in some cases, you will need to specify the format as we have done previously using: `--format=sha512crypt`.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```


# John the Ripper: Single Crack Mode

## Introduction to Single Crack Mode

So far, we’ve been using John’s wordlist mode to brute-force simple and not-so-simple hashes. But John also has another mode, called the **Single Crack mode**. In this mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.

---

## Word Mangling

The best way to explain Single Crack mode and word mangling is to go through an example:

Consider the username **“Markus”**.

Some possible passwords could be:
- Markus1, Markus2, Markus3 (etc.)
- MArkus, MARkus, MARKus (etc.)
- Markus!, Markus$, Markus* (etc.)

This technique is called **word mangling**. John is building its dictionary based on the information it has been fed and uses a set of rules called “mangling rules,” which define how it can mutate the word it started with to generate a wordlist based on relevant factors for the target you’re trying to crack. This exploits how poor passwords can be based on information about the username or the service they’re logging into.

---

## GECOS

John’s implementation of word mangling also features compatibility with the **GECOS** field of the UNIX operating system, as well as other UNIX-like operating systems such as Linux. 

- **GECOS** stands for **General Electric Comprehensive Operating System**.
- In the last task, we looked at the entries for both `/etc/shadow` and `/etc/passwd`. Looking closely, you will notice that the fields are separated by a colon `:`.
- The fifth field in the user account record is the **GECOS field**. It stores general information about the user, such as the user’s full name, office number, and telephone number, among other things.

John can take information stored in those records, such as full name and home directory name, to add to the wordlist it generates when cracking `/etc/shadow` hashes with **single crack mode**.

---

## Using Single Crack Mode

To use single crack mode, we use roughly the same syntax that we’ve used so far. For example, if we wanted to crack the password of the user named **“Mike”**, using the single mode, we’d use:

```bash
john --single --format=[format] [path to file]
```

### Explanation:
- **`--single`**: This flag lets John know you want to use the single hash-cracking mode.
- **`--format=[format]`**: As always, it is vital to identify the proper format.

### Example Usage:

```bash
john --single --format=raw-sha256 hashes.txt
```

---

## A Note on File Formats in Single Crack Mode

If you’re cracking hashes in single crack mode, you need to change the file format that you’re feeding John for it to understand what data to create a wordlist from. 

You do this by prepending the hash with the username that the hash belongs to. 

### Example:

Change the file `hashes.txt`:
**From:**
```
1efee03cdcb96d90ad48ccc7b8666033
```

**To:**
```
mike:1efee03cdcb96d90ad48ccc7b8666033
```

---

## Summary

John the Ripper’s **Single Crack Mode** provides a powerful way to crack hashes by leveraging usernames and other metadata to create customized wordlists based on word mangling rules. This method can be particularly useful for exploiting weak passwords tied to user information.


# Custom Rules in John the Ripper

## What are Custom Rules?

As we explored what John can do in Single Crack Mode, you may have some ideas about good mangling patterns or patterns often used for passwords. The good news is that you can define your rules, which John will use to create passwords dynamically. The ability to define such rules is beneficial when you know more information about the password structure of whatever your target is.

## Common Custom Rules

Many organisations require password complexity to combat dictionary attacks. For example, passwords must contain at least one character from each category:

- Lowercase letter
- Uppercase letter
- Number
- Symbol

Predictable password patterns often emerge, such as:

```
Polopassword1!
```

This pattern includes a capital letter first, a number, and a symbol at the end. Attackers can exploit predictable patterns to create dynamic passwords.

## How to Create Custom Rules

Custom rules are defined in the `john.conf` file. This file is located in `/opt/john/john.conf` on the TryHackMe Attackbox and `/etc/john/john.conf` if installed via a package manager.

### Syntax

- `[List.Rules:RuleName]`: Defines the name of your rule, used as a John argument.
- Modifiers:
  - `Az`: Appends characters to the end of the word.
  - `A0`: Prepends characters to the word.
  - `c`: Capitalises positional characters.
- Character sets:
  - `[0-9]`: Numbers 0-9.
  - `[A-Z]`: Uppercase letters.
  - `[a-z]`: Lowercase letters.
  - `[!£$%@]`: Specific symbols.

### Example

To match the password `Polopassword1!`, assuming `polopassword` is in the wordlist:

```
[List.Rules:PoloPassword]
cAz"[0-9][!£$%@]"
```

This rule:
- `c`: Capitalises the first letter.
- `Az`: Appends characters to the end.
- `[0-9]`: Adds a number.
- `[!£$%@]`: Adds a symbol.

## Using Custom Rules

Call the custom rule with the `--rule` flag:

```
john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]
```

## Notes
- Jumbo John includes extensive pre-built rules you can reference. Check around line 678 in `john.conf` if you need examples or troubleshooting help.


# Using Zip2John and Cracking Password-Protected Zip Files

Yes! You read that right. We can use John to crack the password on password-protected Zip files. Again, we’ll use a separate part of the John suite of tools to convert the Zip file into a format that John will understand, but we’ll use the syntax you’re already familiar with for all intents and purposes.

## Zip2John
Similarly to the unshadow tool we used previously, we will use the `zip2john` tool to convert the Zip file into a hash format that John can understand and hopefully crack. The primary usage is like this:

```bash
zip2john [options] [zip file] > [output file]
```

- `[options]`: Allows you to pass specific checksum options to `zip2john`; this shouldn’t often be necessary.
- `[zip file]`: The path to the Zip file you wish to get the hash of.
- `>`: This redirects the output from this command to another file.
- `[output file]`: This is the file that will store the output.

### Example Usage
```bash
zip2john zipfile.zip > zip_hash.txt
```

## Cracking
We’re then able to take the file we output from `zip2john` in our example use case, `zip_hash.txt`, and, as we did with `unshadow`, feed it directly into John as we have made the input specifically for it.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

By providing the wordlist, John will brute force the password from the generated hash file, enabling you to recover the password for the protected zip file.


# Cracking a Password-Protected RAR Archive

We can use a similar process to the one we used in the last task to obtain the password for RAR archives. If you aren’t familiar, RAR archives are compressed files created by the WinRAR archive manager. Like Zip files, they compress folders and files.

## Rar2John

Almost identical to the `zip2john` tool, we will use the `rar2john` tool to convert the RAR file into a hash format that John can understand. The basic syntax is as follows:

```bash
rar2john [rar file] > [output file]
```

### Explanation:
- `rar2john`: Invokes the `rar2john` tool.
- `[rar file]`: The path to the RAR file you wish to get the hash of.
- `>`: This redirects the output of this command to another file.
- `[output file]`: This is the file that will store the output from the command.

### Example Usage:

```bash
/opt/john/rar2john rarfile.rar > rar_hash.txt
```

## Cracking

Once again, we can take the file we output from `rar2john` in our example use case, `rar_hash.txt`, and feed it directly into John as we did with `zip2john`.

### Cracking Command:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
```


# Cracking SSH Key Passwords

John the Ripper can also crack passwords for SSH private keys, such as the `id_rsa` file. This comes in handy during CTF challenges or penetration tests where key-based authentication is used. Here's how to crack the password for an SSH private key.

## Step 1: Convert the SSH Key to a Hash Format

We use the `ssh2john` or `ssh2john.py` tool to convert the `id_rsa` private key into a hash format that John can understand.

### Syntax
```bash
ssh2john [id_rsa private key file] > [output file]
```

### Parameters
- **ssh2john**: Invokes the ssh2john tool.
- **[id_rsa private key file]**: The path to the private key file you want to crack.
- **>**: Redirects the output from the command to a file.
- **[output file]**: The file where the converted hash will be saved.

### Example
If using the AttackBox or Kali Linux, you might need to call the Python script directly:

```bash
python3 /opt/john/ssh2john.py id_rsa > id_rsa_hash.txt
```

## Step 2: Crack the Hash

Feed the output file generated by `ssh2john` (e.g., `id_rsa_hash.txt`) into John the Ripper to crack the password.

### Syntax
```bash
john --wordlist=[path to wordlist] [path to hash file]
```

### Parameters
- **--wordlist**: Specifies the wordlist to use, such as `rockyou.txt`.
- **[path to wordlist]**: The path to the wordlist file.
- **[path to hash file]**: The file containing the hash generated by `ssh2john`.

### Example
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```

## Summary

1. Convert the SSH private key to a hash format using `ssh2john`.
2. Crack the password for the key using John the Ripper.

These steps enable you to recover the password and use the private key for SSH authentication.

---
**Note**: Always ensure you have proper authorization before attempting any cracking activities.
