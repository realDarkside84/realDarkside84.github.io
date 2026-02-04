---
title: "TakeOver - TryHackMe"
author: Dark_side.84
categories: [TryHackMe]
tags: [web, enumeration, subdomain-enum, ffuf, vhost, http, https, ssl, certificate, php, apache2, docker, linux, pivoting, curl]
render_with_liquid: false
image: /images/tryhackme_TakeOver/room_image.webp
---

TakeOver - TryHackMe

**TakeOver** focuses on web enumeration and virtual host discovery. The challenge began by adding the target domain to the local hosts file to ensure proper name resolution. Initial enumeration was performed against the web service, leading to the discovery of multiple virtual hosts through **subdomain fuzzing**.

Using **ffuf**, valid subdomains were identified by filtering responses based on size and status codes. Each discovered subdomain was then mapped locally and analyzed individually. During this process, differences between **HTTP** and **HTTPS** responses were observed, indicating misconfigured services.

Further inspection of the **HTTPS** service revealed useful information within the **SSL certificate**, which exposed hidden details related to the challenge. Navigating to the identified endpoint ultimately led to the discovery of the flag, completing the room.

[![TryHackMe Room Link](/images/tryhackme_TakeOver/room_image.webp){: width="300" height="300" .shadow}](https://tryhackme.com/room/takeover){: .center }


## Hosts File Configuration

Before interacting with the web application, the target domain was mapped locally to ensure proper name resolution. The following entry was added to the `/etc/hosts` file:

```bash
10.48.176.123  futurevera.thm
```
Once added, the domain was accessible via the browser using `https://futurevera.thm`.

## Subdomain Enumeration and Exploitation

To begin the fuzzing process, a baseline response size must first be established. This is done by requesting a non-existent subdomain, which allows us to identify the standard response for a "Not Found" or default page. This baseline will be used to filter out uninteresting results during the automated scan:

```bash 
curl -I -k -H "Host: randomname.futurevera.thm" https://futurevera.thm
```

![TakeOver Curl](/images/tryhackme_TakeOver/curl.png){: width="1200" height="600"}

The initial request confirms that an invalid subdomain returns a response size of **4,605 bytes**. Since this represents the default error page or "not found" response, any valid subdomain will likely return a different value. To isolate meaningful results, we must filter out these false positives, as well as any empty responses (0 bytes). With this baseline established, the `ffuf` command was configured to exclude these specific sizes, ensuring only unique virtual hosts are identified:

```bash
ffuf -H "Host: FUZZ.futurevera.thm" -u https://10.48.176.123 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 0,4605
```

![ffuf one](/images/tryhackme_TakeOver/ffuf.png){: width="1200" height="600"}

The fuzzing process successfully identified two unique subdomains. To ensure proper connectivity and allow the browser to resolve these new hostnames, they must be mapped to the target IP address within the `/etc/hosts` file:

```bash
echo "10.48.176.123  support.futurevera.thm blog.futurevera.thm" | sudo tee -a /etc/hosts 
```

Now the next step is to perform a directory scan to locate any hidden files or folders use the following command:

```bash
ffuf -u https://support.futurevera.thm/FUZZ -w /usr/share/wordlists/rockyou.txt
```

![ffuf with rockyou.txt ](/images/tryhackme_TakeOver/ffuf_rockyou.png){: width="1200" height="600"}

we have more dircetories cz as you can see the scan is still running and as you can see the scan returned several false positives with a size of 1,522 bytes. To clean up the results, the command was re-run with a filter to exclude both the 0 and **1,522-byte** response sizes:

```bash
ffuf -u https://support.futurevera.thm/FUZZ -w /usr/share/wordlists/rockyou.txt -fs 0,1522
```

The `rockyou.txt` wordlist is quite extensive, and the high volume of requests significantly impacted the scanning speed. To maintain performance, the process was manually terminated:

![ffuf support with rockyou.txt ](/images/tryhackme_TakeOver/ffuf_support_rockyou.png){: width="1200" height="600"}

The scan only revealed an `/assets` directory, which did not yield any useful information. After reviewing the progress so far, a more detailed manual inspection of the identified hosts was conducted using `curl`.

During this inspection, a discrepancy was noted: the command:
```bash
curl https://support.futurevera.thm --verbose 
```
hung for an extended period before returning a certificate error. In contrast, the plaintext version,
```bash
curl http://support.futurevera.thm --verbose
```
provided an immediate response.

![curl compare](/images/tryhackme_TakeOver/compare.webp){: width="1200" height="600"}

A notable distinction exists between the **HTTP** and **HTTPS** versions of the site. While the HTTPS version loads in the browser, the previous `curl` errors suggest an underlying issue. To investigate further, we will re-examine the site's SSL/TLS certificate directly through the browser:

![Website certificate dns](/images/tryhackme_TakeOver/website%20cert.webp){: width="1200" height="600"}

It looks like we have found a hint here. Now let’s add this page to our DNS configuration file and try opening it in the browser:

![ flag in url](/images/tryhackme_TakeOver/flag.webp){: width="1200" height="600"}

After further investigation, the effort paid off as we successfully captured the flag from two separate locations:

**Answer: flag{beea0d6edfcee06a59b83fb50ae81b2f}**

## Conclusion 

While this room focused more on meticulous observation than advanced technical knowledge, the discovery-based progression provided a realistic perspective on the trial-and-error nature of penetration testing.

Throughout this writeup, I aimed to document both successful methods and failed attempts. By highlighting these roadblocks, I hope to provide beginners with a clearer understanding of the troubleshooting process. I hope you found this guide helpful!

Best regards Dark_side84 <3


