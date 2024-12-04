
# Hashing vs. Encryption

## Hashing

Hashing is the process of converting some text into a string that is unique to that particular text. A hash function always returns hashes with the same length, irrespective of the type, length, or size of the data. Hashing is a one-way process, meaning there is no way to reconstruct the original plaintext from a hash. 

### Uses of Hashing

Hashing can be used for various purposes:
- **File Integrity Verification**: Algorithms like MD5 and SHA256.
- **Password Hashing**: Algorithms such as PBKDF2 to hash passwords before storage.
- **Message Authentication**: Algorithms like HMAC act as a checksum to verify message integrity during transmission.

### Examples of Hashing Algorithms

| Algorithm  | Features                                                                                          |
|------------|--------------------------------------------------------------------------------------------------|
| **SHA-512**| Efficient but susceptible to rainbow table attacks if not salted.                               |
| **Blowfish**| Symmetric block cipher algorithm, slower but more secure than SHA-512.                         |
| **BCrypt** | Slow hashing to prevent rainbow table attacks and make brute force computationally expensive.   |
| **Argon2** | Modern, secure, and designed for password hashing with high resource and time requirements.     |

### Example: MD5 Hashing
```bash
echo -n "p@ssw0rd" | md5sum
# Output: 0f359740bd1cda994f8b55330c86d845
```

### Example: Adding Salt
```bash
echo -n "p@ssw0rd123456" | md5sum
# Output: f64c413ca36f5cfe643ddbec4f7d92d0
```

Adding a random salt such as "123456" changes the hash completely, making precomputed rainbow tables ineffective.

---

## Encryption

Encryption is the process of converting data into an unreadable format to protect its contents. Unlike hashing, encryption is **reversible**, meaning ciphertext (encrypted data) can be decrypted to retrieve the original plaintext.

### Types of Encryption

1. **Symmetric Encryption**
   - Uses the same key for encryption and decryption.
   - Example: XOR encryption.

   ```python
   from pwn import xor
   ciphertext = xor("p@ssw0rd", "secret")
   print(ciphertext)
   # Output: b'%D'
   plaintext = xor(ciphertext, "secret")
   print(plaintext)
   # Output: b'p@ssw0rd'
   ```

   - Common algorithms: AES, DES, 3DES, Blowfish.
   - Vulnerabilities: Key brute-forcing, frequency analysis, padding oracle attacks.

2. **Asymmetric Encryption**
   - Divides the key into a public key and a private key.
   - The public key encrypts data, while the private key decrypts it.
   - Examples: RSA, ECDSA, Diffie-Hellman.

   - Use case: HTTPS. During an HTTPS connection, a public key is exchanged to encrypt data sent to the server, which is decrypted using the private key.

---

## Key Differences Between Hashing and Encryption

| Feature         | Hashing                                           | Encryption                                      |
|-----------------|--------------------------------------------------|------------------------------------------------|
| **Reversibility**| One-way, irreversible.                          | Two-way, reversible using decryption keys.    |
| **Purpose**     | Verify integrity, store passwords securely.      | Protect data confidentiality during transfer. |
| **Example**     | MD5, SHA-512, Argon2.                            | AES, RSA, SSL/TLS protocols.                  |


# Identifying Hashes

## Overview
Most hashing algorithms produce hashes of a constant length. The length of a particular hash can be used to map it to the algorithm it was hashed with. For example, a hash of 32 characters in length can be an **MD5** or **NTLM** hash.

### Hash Formats
Sometimes, hashes are stored in specific formats, such as:
- `hash:salt`
- `$id$salt$hash`

Example:
- The hash `2fc5a684737ce1bf7b3b239df432416e0dd07357:2014` is a **SHA1 hash** with the salt of `2014`.
- The hash `$6$vb1tLY1qiY$M.1ZCqKtJBxBtZm1gRi8Bbkn39KU0YJW1cuMFzTRANcNKFKR4RmAQVk4rqQQCkaJT6wXqjUkFcA/qNxLyqW.U/` has three fields:
  - `$6$`: Identifier for the algorithm (SHA512)
  - `vb1tLY1qiY`: Salt
  - The final field: The actual hash

### Common Hash Identifiers
| ID    | Algorithm                         |
|-------|-----------------------------------|
| `$1$` | MD5                               |
| `$2a$`| Blowfish                          |
| `$2y$`| Blowfish (handles 8-bit chars)    |
| `$5$` | SHA256                            |
| `$6$` | SHA512                            |

---

## Identifying Hashes with `hashid`

**Hashid** is a Python tool capable of identifying over 200 unique hash types. It guesses the hash type using regex patterns and provides the best possible match.

### Installation
```bash
pip install hashid
```

### Usage
Hashes can be supplied as command-line arguments or through a file.

#### Command-Line Input
```bash
hashid '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.'
```

**Output:**
```
Analyzing '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.'
[+] MD5(APR)
[+] Apache MD5
```

#### File Input
```bash
hashid hashes.txt
```

**Output:**
```
--File 'hashes.txt'--
Analyzing '2fc5a684737ce1bf7b3b239df432416e0dd07357:2014'
[+] SHA-1
[+] Double SHA-1
[+] RIPEMD-160
...
Analyzing '$P$984478476IagS59wHZvyQMArzfx58u.'
[+] Wordpress ≥ v2.6.2
[+] Joomla ≥ v2.5.18
[+] PHPass' Portable Hash
--End of file 'hashes.txt'--
```

#### Displaying Hashcat Modes
If known, **hashid** can provide the corresponding Hashcat mode with the `-m` flag.

Example:
```bash
hashid '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' -m
```

**Output:**
```
Analyzing '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f'
[+] Domain Cached Credentials 2 [Hashcat Mode: 2100]
```

---

## Context is Key
When identifying hashes, context matters. Understanding where the hash was obtained can narrow down its type. For example:
- Was it obtained from Active Directory?
- Was it the result of a SQL injection vulnerability?

### Example
The hash `a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com` yields multiple possible matches with **hashid**:
```bash
hashid 'a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com'
```

**Output:**
```
Analyzing 'a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com'
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
...
[+] Lastpass
```

By reviewing the [Hashcat example hashes reference](https://hashcat.net/wiki/doku.php?id=example_hashes), you can determine this is a **Lastpass hash** with Hashcat mode `6800`.

---

## Summary
1. Hash formats may include salts and identifiers.
2. Use **hashid** to identify possible algorithms and Hashcat modes.
3. Context helps narrow down the type of hash and associated cracking methods.
4. Consult resources like the [Hashcat example hashes reference](https://hashcat.net/wiki/doku.php?id=example_hashes) for additional clarity.


# Hashcat Overview

## Hashcat

Hashcat is a popular open-source password cracking tool.

Hashcat can be downloaded from the website using `wget` and then decompressed using the `7z` (7-Zip file archiver) via the command line. The full help menu can be viewed by typing `hashcat -h`. The latest version of Hashcat at the time of writing is version 6.1.1. Version 6.0.0 was a major release that introduced several enhancements over version 5.x. Some of the changes include performance improvements and 51 new algorithms (or supported hash types, also known as hash modes) for a total of over 320 supported algorithms at the time of writing.

Hashcat binaries for Windows and Unix/Linux systems can be downloaded as a standalone binary or compiled from the source. The latest version can always be obtained directly from their GitHub repository. For demonstration purposes, installation on Pwnbox (v6.1.1) is provided below.

## Hashcat Installation

```bash
sudo apt install hashcat
hashcat -h
```

Output of `hashcat -h`:

```plaintext
hashcat (v6.1.1) starting...

Usage: hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]...

- [ Options ] -

Options Short / Long           | Type | Description                                          | Example
================================+======+======================================================+=======================
 -m, --hash-type                | Num  | Hash-type, see references below                      | -m 1000
 -a, --attack-mode              | Num  | Attack-mode, see references below                    | -a 3
 -V, --version                  |      | Print version                                        |
 -h, --help                     |      | Print help                                           |
 --quiet                        |      | Suppress output                                      |
 --hex-charset                  |      | Assume charset is given in hex                       |
 --force                        |      | Ignore warnings                                      |
 ...
```

### Attack Modes

Hashcat supports the following attack modes:

| #   | Mode                     |
|-----|--------------------------|
| 0   | Straight                 |
| 1   | Combination              |
| 3   | Brute-force              |
| 6   | Hybrid Wordlist + Mask   |
| 7   | Hybrid Mask + Wordlist   |

The hash type value is based on the algorithm of the hash to be cracked. A complete list of hash types and their corresponding examples can be found in the Hashcat documentation.

### Example Hashes

View a list of example hashes with:

```bash
hashcat --example-hashes | less
```

Example output:

```plaintext
MODE: 0
TYPE: MD5
HASH: 8743b52063cd84097a65d1633f5c74f5
PASS: hashcat

MODE: 10
TYPE: md5($pass.$salt)
HASH: 3d83c8e717ff0e7ecfe187f088d69954:343141
PASS: hashcat
```

### Benchmarking

You can test the performance of a particular hash type using the `-b` flag:

```bash
hashcat -b -m 0
```

Example output:

```plaintext
Hashmode: 0 - MD5
Speed.#1.........: 449.4 MH/s (12.84ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8
```

To benchmark all hash modes, run:

```bash
hashcat -b
```

## Hashcat Optimizations

Hashcat offers two main ways to optimize speed:

| Option               | Description                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------|
| Optimized Kernels    | The `-O` flag enables optimized kernels (limits password length, generally to 32 characters). |
| Workload Profile     | The `-w` flag adjusts the workload. Default is `2`, but `3` is optimal for dedicated cracking.|

**Note:** Avoid using `--force` unless necessary. It bypasses safety checks and can lead to false results or malfunctions.


# Dictionary Attack

## Overview
Hashcat has 5 different attack modes that have different applications depending on the type of hash you are trying to crack and the complexity of the password. The most straightforward but extremely effective attack type is the dictionary attack. It is not uncommon to encounter organizations with weak password policies whose users select common words and phrases with little to no complexity as their passwords.

### Password List - Top 5 (2020)
1. 123456
2. 123456789
3. qwerty
4. password
5. 1234567

Despite training users on security awareness, users will often choose one out of convenience if an organization allows weak passwords.

## Sources for Password Lists
- **SecLists**: A large collection of password lists.
- **Rockyou.txt**: Found in most penetration testing Linux distros.
- **CrackStation's Dictionary**: Contains 1.49 billion words (15GB in size).

## Straight or Dictionary Attack
This attack reads from a wordlist and tries to crack the supplied hashes. It is typically faster to complete than more complex attacks.

### Syntax
```bash
hashcat -a 0 -m <hash type> <hash file> <wordlist>
```

### Example
Crack a SHA256 hash using the `rockyou.txt` wordlist:
```bash
# Create a hash file
echo -n '!academy' | sha256sum | cut -f1 -d' ' > sha256_hash_example

# Run Hashcat
hashcat -a 0 -m 1400 sha256_hash_example /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

#### Output
```
hashcat (v6.1.1) starting...

<SNIP>

006fc3a9613f3edd9f97f8e8a8eff3b899a2d89e1aabf33d7cc04fe0728b0fe6:!academy
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-256
Time.Started.....: Fri Aug 28 21:58:44 2020 (4 secs)
Time.Estimated...: Fri Aug 28 21:58:48 2020 (0 secs)
```

### More Complex Hash Example
#### Bcrypt
The bcrypt hash of `!academy` with 5 rounds of Blowfish algorithm applied:
```bash
$2a$05$ZdEkj8cup/JycBRn2CX.B.nIceCYR8GbPbCCg6RlD7uvuREexEbVy
```

#### Status During Cracking
```bash
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Time.Estimated...: 1 hour, 33 mins
Speed.#1.........: 2470 H/s
Progress.........: 468576/14344385 (3.27%)
```

## Observations
Dictionary attacks are effective for weak passwords, but the success depends on:
- The complexity of the password.
- The hashing algorithm in use.
- The hardware used for cracking.

Certain types of weak passwords may be harder to crack just based on the algorithm, but a strong password policy combined with a robust hashing algorithm is essential to improve security.

Ejercicio
  Crack the following hash using the rockyou.txt wordlist: 0c352d5b2f45217c57bef9f8452ce376
      ```vhashcat -a 0 -m 0 0c352d5b2f45217c57bef9f8452ce376 /usr/share/wordlists/rockyou.txt```



# Combination Attack

## Overview
The combination attack modes take in two wordlists as input and create combinations from them. This attack is useful because it is not uncommon for users to join two or more words together, thinking that this creates a stronger password, e.g., `welcomehome` or `hotelcalifornia`.

### Example Wordlists

#### Wordlist 1
```
super
world
secret
```

#### Wordlist 2
```
hello
password
```

If given these two wordlists, Hashcat will produce exactly \(3 	imes 2 = 6\) words, such as:

```
superhello
superpassword
worldhello
worldpassword
secrethello
secretpassword
```

### Using Hashcat to Combine Wordlists
This can be done with Hashcat using the `--stdout` flag, which can be very helpful for debugging purposes and seeing how the tool handles things.

#### Example:
```bash
hashcat -a 1 --stdout wordlist1 wordlist2
```

#### Output:
```
superhello
superpassword
worldhello
worldpassword
secrethello
secretpassword
```

## Syntax for Combination Attack
The syntax for a combination attack is as follows:

```bash
hashcat -a 1 -m <hash_type> <hash_file> <wordlist1> <wordlist2>
```

This attack provides more flexibility and customization when using wordlists.

---

## Practical Example

### Step 1: Create the MD5 Hash
First, create the MD5 hash of the password `secretpassword`:
```bash
echo -n 'secretpassword' | md5sum | cut -f1 -d' ' > combination_md5
```

Result:
```
2034f6e32958647fdff75d265b455ebf
```

### Step 2: Run Hashcat
Next, run Hashcat against the hash using the two wordlists with the combination attack mode:
```bash
hashcat -a 1 -m 0 combination_md5 wordlist1 wordlist2
```

### Output:
```
hashcat (v6.1.1) starting...

<SNIP>

2034f6e32958647fdff75d265b455ebf:secretpassword
```

## Supplementary Wordlists for Practice

### Wordlist 1
```
sunshine
happy
frozen
golden
```

### Wordlist 2
```
hello
joy
secret
apple
```

Combination attacks are another powerful tool to keep in our arsenal. As demonstrated above, merely combining two words does not necessarily make a password stronger.

Using the Hashcat combination attack find the cleartext password of the following md5 hash:
  Antes hay que hacer los ficheros que nos manda el ejercicio
    ```└─$ hashcat -a 1 -m 0 combination_md5 wordlist1 wordlist2```



# Mask Attack

Mask attacks are used to generate words matching a specific pattern. This type of attack is particularly useful when the password length or format is known. A mask can be created using static characters, ranges of characters (e.g. `[a-z]` or `[A-Z0-9]`), or placeholders. The following list shows some important placeholders:

| Placeholder | Meaning                                   |
|-------------|-------------------------------------------|
| ?l          | lower-case ASCII letters (a-z)           |
| ?u          | upper-case ASCII letters (A-Z)           |
| ?d          | digits (0-9)                             |
| ?h          | 0123456789abcdef                         |
| ?H          | 0123456789ABCDEF                         |
| ?s          | special characters (`«space»!"#$%&'()*+,-./:;<=>?@[]^_`\{`) |
| ?a          | ?l?u?d?s                                 |
| ?b          | 0x00 - 0xff                              |

The above placeholders can be combined with options `-1` to `-4`, which can be used for custom placeholders. See the [Custom charsets](https://hashcat.net/wiki/doku.php?id=hashcat) section for a detailed breakdown of each of these four command-line parameters that can be used to configure four custom charsets.

### Example

Consider the company Inlane Freight, which this time has passwords with the scheme `ILFREIGHT<userid><year>`, where `userid` is 5 characters long. The mask `ILFREIGHT?l?l?l?l?l20[0-1]?d` can be used to crack passwords with the specified pattern, where `?l` is a letter and `20[0-1]?d` will include all years from 2000 to 2019.

#### Creating MD5 Hashes

```bash
echo -n 'ILFREIGHTabcxy2015' | md5sum | tr -d " -" > md5_mask_example_hash
```

#### Mask Attack with Hashcat

In the below example, the attack mode is `3`, and the hash type for MD5 is `0`.

```bash
hashcat -a 3 -m 0 md5_mask_example_hash -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'
```

#### Output

```
hashcat (v6.1.1) starting...
<SNIP>

d53ec4d0b37bbf565b1e09d64834e1ae:ILFREIGHTabcxy2015
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: d53ec4d0b37bbf565b1e09d64834e1ae
Time.Started.....: Fri Aug 28 22:08:44 2020, (43 secs)
Time.Estimated...: Fri Aug 28 22:09:27 2020, (0 secs)
Guess.Mask.......: ILFREIGHT?l?l?l?l?l20?1?d [18]
Guess.Charset....: -1 01, -2 Undefined, -3 Undefined, -4 Undefined 
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3756.3 kH/s (0.36ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 155222016/237627520 (65.32%)
Rejected.........: 0/155222016 (0.00%)
Restore.Point....: 155215872/237627520 (65.32%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: ILFREIGHTuisba2015 -> ILFREIGHTkmrff2015
```

The `-1` option was used to specify a placeholder with just `0` and `1`. Hashcat could crack the hash in 43 seconds on CPU power. The `--increment` flag can be used to increment the mask length automatically, with a length limit that can be supplied using the `--increment-max` flag.

Crack the following MD5 hash using a mask attack: 50a742905949102c961929823a2e8ca0. Use the following mask: -1 02 'HASHCAT?l?l?l?l?l20?1?d'
  ```└─$ hashcat -a 3 -m 0 cobination_md5 -1 02 'HASHCAT?l?l?l?l?l20?1?d'```


# Summary of Hybrid Mode in Hashcat

## What is Hybrid Mode?
Hybrid mode is a variation of the combinator attack, allowing multiple modes to work together for customized wordlist creation. It is particularly effective for creating targeted attacks when the password policy or common password syntax of an organization is known. Attack mode "6" is used for appending characters, while "7" is used for prepending them.

---

## Example: Appending Characters with Attack Mode 6
1. **Password:** `football1$`
2. **Command:** 
   ```bash
   echo -n 'football1$' | md5sum | tr -d " -" > hybrid_hash
   hashcat -a 6 -m 0 hybrid_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt '?d?s'
   ```
3. **Mask Explanation:** `?d?s` appends a digit and a special character to each word.
4. **Output:**
   - Hash cracked: `f7a4a94ff3a722bf500d60805e16b604`
   - Password: `football1$`

---

## Example: Prepending Characters with Attack Mode 7
1. **Password:** `2015football`
2. **Command:** 
   ```bash
   echo -n '2015football' | md5sum | tr -d " -" > hybrid_hash_prefix
   hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
   ```
3. **Mask Explanation:** `20?1?d` with `-1 01` prepends years (e.g., 2010, 2011) to each word.
4. **Output:**
   - Hash cracked: `eac4fe196339e1b511278911cb77d453`
   - Password: `2015football`

---

## Key Features of Hybrid Mode
- **Flexibility:** Combines wordlists with masks to generate fine-tuned password guesses.
- **Efficiency:** Targets passwords based on known patterns like prefixes or suffixes.
- **Speed:** High performance for large-scale hash cracking operations.

---

Ejercicio
  Crack the following hash: 978078e7845f2fb2e20399d9e80475bc1c275e06 using the mask ?d?s.
    ```hashcat -a 6 -m 100 978078e7845f2fb2e20399d9e80475bc1c275e06 /usr/share/wordlists/rockyou.txt "?d?s"```


  
# Summary: Creating Custom Wordlists

## Importance of Custom Wordlists
- Custom wordlists are crucial when common wordlists fail to crack hashes.
- Wordlists can be tailored using target information and refined using rules.
- SecLists is a great repository for useful wordlists.

---

## Tools for Custom Wordlists

### Crunch
- **Usage:** Generate wordlists based on length, character set, or patterns.
- **Syntax:**
  ```bash
  crunch <min length> <max length> <charset> -t <pattern> -o <output file>
  ```
- **Examples:**
  - Default wordlist:
    ```bash
    crunch 4 8 -o wordlist
    ```
  - Patterned wordlist:
    ```bash
    crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist
    ```

### CUPP (Common User Password Profiler)
- **Purpose:** Create wordlists based on personal information (e.g., names, birthdays).
- **Interactive Mode Example:**
  ```bash
  python3 cupp.py -i
  ```
- **Features:** Supports random characters, "leet" mode, and OSINT integration.

### KWProcessor
- **Purpose:** Generate wordlists using keyboard walk patterns.
- **Installation:**
  ```bash
  git clone https://github.com/hashcat/kwprocessor
  cd kwprocessor
  make
  ```
- **Example Command:**
  ```bash
  kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route
  ```

### PrinceProcessor
- **Purpose:** Generate wordlists with chained permutations from input words.
- **Installation:**
  ```bash
  wget https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z
  7z x princeprocessor-0.22.7z
  cd princeprocessor-0.22
  ./pp64.bin -h
  ```
- **Example Command:**
  ```bash
  ./pp64.bin -o wordlist.txt < words
  ```

### CeWL
- **Purpose:** Scrape websites to create wordlists based on content.
- **Syntax:**
  ```bash
  cewl -d <depth> -m <min word length> -w <output file> <url>
  ```
- **Example:**
  ```bash
  cewl -d 5 -m 8 -e http://example.com -w wordlist.txt
  ```

---

## Additional Techniques

### Hashcat Potfile
- Use cracked passwords from `hashcat.potfile` to create new wordlists:
  ```bash
  cut -d: -f 2- ~/hashcat.potfile
  ```

### Hashcat-utils
- Maskprocessor generates wordlists with specified masks:
  ```bash
  ./mp64.bin Welcome?s
  ```
- Outputs variations like `Welcome!`, `Welcome#`, etc.

---

## Key Takeaways
- Custom wordlists improve cracking success rates when common lists fail.
- Tools like Crunch, CUPP, and PrinceProcessor provide diverse generation methods.
- CeWL and KWProcessor exploit target-specific patterns and behaviors.

  
# Summary: Cracking Common Hashes

## Common Hash Types
- **MD5** (Hash Mode 0): `8743b52063cd84097a65d1633f5c74f5`
- **SHA1** (Hash Mode 100): `b89eaac7e61417341b710b727768294d0e6a277b`
- **NTLM** (Hash Mode 1000): `b4b9b02e6f09a9bd760f388b67351e2b`
- **SHA512crypt (Unix)** (Hash Mode 1800): `$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/`
- **bcrypt (Unix)** (Hash Mode 3200): `$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6`
- **NetNTLMv1** (Hash Mode 5500): `u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000`
- **NetNTLMv2** (Hash Mode 5600): `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6`
- **Kerberos 5 TGS-REP (etype 23)** (Hash Mode 13100): `$krb5tgs$23$user$realm$test/spn$63386d22d359fe42230300d56852c9eb`

---

## Examples of Hash Cracking

### Example 1: Database Dumps
- **Scenario:** SHA1 hashes retrieved from a database.
- **Command:** Generate hashes for a wordlist:
  ```bash
  for i in $(cat words); do echo -n $i | sha1sum | tr -d ' -';done
  ```
- **Hashcat Command:** 
  ```bash
  hashcat -m 100 SHA1_hashes /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
  ```
- **Result:** Cracked simple SHA1 hashes (e.g., `sunshine1`, `welcome1`).

### Example 2: Linux Shadow File
- **Scenario:** SHA512crypt hashes from `/etc/shadow`.
- **Command:** Crack SHA512crypt hash:
  ```bash
  hashcat -m 1800 nix_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
  ```
- **Result:** Cracked root password (`password123`).

### Example 3: NTLM Hashes
- **Scenario:** NTLM hash generated using Python.
- **Command:** Generate NTLM hash:
  ```python
  >>> import hashlib,binascii
  >>> hash = hashlib.new('md4', "Password01".encode('utf-16le')).digest()
  >>> print (binascii.hexlify(hash))
  ```
- **Hashcat Command:**
  ```bash
  hashcat -a 0 -m 1000 ntlm_example /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
  ```
- **Result:** Cracked NTLM hash (`Password01`).

### Example 4: NetNTLMv2 Hashes
- **Scenario:** Captured NetNTLMv2 hash using Responder.
- **Hashcat Command:**
  ```bash
  hashcat -a 0 -m 5600 inlanefreight_ntlmv2 /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
  ```
- **Result:** Cracked hash (`Database99`).

---

## Key Takeaways
- **Hash Types:** Familiarize with common hash modes for efficiency.
- **Dictionary Attacks:** Leverage tools like `Hashcat` with extensive wordlists (e.g., `rockyou.txt`).
- **Offline Cracking:** Essential for hashes like NetNTLMv2 and NTLM.
- **Privilege Escalation:** Cracked hashes can often lead to further attacks within a target environment.



