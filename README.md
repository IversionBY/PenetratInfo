#### Table of contents
- [PentestInfo](#PentestInfo)
    - [0X01 Information Gethering](#0X01-Information-Gethering)
        - [IP And DNS](#IP-And-DNS)
        - [Information leakage](#Information-leakage)
    - [0X02 Denial Of Service](#0X02-Denial-Of-Service)
    - [0X03 Scan](#0X03-Scan)
        - [Identify](#Identify)
        - [Tools For Overall Scan](#Tools-For-Overall-Scan)
        - [Web Applications Scan Tools](#Web-Applications-Scan-Tools)
    - [0X04 Fuzz and Password](#0X04-Fuzz-and-Password)
    - [0X05 Password crack](#0X05-Password-Hash)
    - [0X06 System Vulnerability](#0X06-System-Vulnerability)
    - [0X07 Web Relevant Online Website](#0X07-Web-Relevant-Online-Website)
    - [0X08 Existing Vulnerability Finding](#0X08-Existing-Vulnerability-Finding)
    - [0X09 Cheatsheet](#0X09-Cheatsheet)
    - [0X10 Webshell And Payload](#0X10-Webshell-And-Payload)
    - [0X11 Code Review And Some Challeges](#0X11-Code-Review-And-Some-Challeges)
    - [0X12 Code Review Scan Tools](#0X12-Code-Review-Scan-Tools)
    - [0X13 Frameworks and Components POC](#0X13-Frameworks-and-Components-POC)
    - [0X14 Malicious File Detection](#0X14-Malicious-File-Detection)
    - [0X15 Port Foward](#0X15-Port-Foward)
    - [0X16 Backdoor](#0X16-Backdoor)
    - [0X17 Intranet Domain Penetration](#0X17-Intranet-Domain-Penetration)
    - [0X18 Wifi Attack Relevant](#0X18-Wifi-Attack-Relevant)
    - [0X19 After Penetration](#0X19-After-Penetration)
    - [0X20 MISC(Brute force,encode,decode,cipher)](#0X20-MISC(Brute-force,encode,decode,cipher))
    - [0x21 Vulnerability System](#0x21-Vulnerability-System)
    - [0x22 Learn More](#0x22-Learn-More)
    - [standard](#Other-Resource)


# PentestInfo
Some tools and websites may useful in penetration.

## 0X01 Information Gethering 

### IP And DNS
- [Shodan](https://www.shodan.io/)
- [Zoomeye](https://www.zoomeye.org/)
- [censys](https://censys.io/)
- [Advantage search grammar](https://thief.one/2017/05/19/1/)
- [netcraft](https://www.netcraft.com/)
- [ssl certificate search](https://crt.sh)
- [Myssl](https://myssl.com/)
- [ssltest](https://www.ssllabs.com/ssltest/)
- [zone-transger](https://hackertarget.com/zone-transfer/)
- [lookup dns records](https://dnsdumpster.com/)
- [threatbook](https://x.threatbook.cn/)
- [List_of_TCP_and_UDP_port_numbers](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
- [CertDB](https://certdb.com/domain/github.com)
- [tko-subs](https://github.com/anshumanbh/tko-subs) A tool that can help detect and takeover subdomains with dead DNS records.

### Information leakage
- [GitHack](https://github.com/lijiejie/GitHack) `.git` folder disclosure exploit
- [x-patrol](https://github.com/MiSecurity/x-patrol) github leakage information gathering
- [repo-security-scanner](https://github.com/UKHomeOffice/repo-security-scanner) CLI tool that finds secrets accidentally committed to a git repo, eg passwords, private keys
- [dvcs-ripper](https://github.com/kost/dvcs-ripper) Rip web accessible (distributed) version control systems
- [svnExploit](https://github.com/admintony/svnExploit/)
- [Swp found cmd: vim -r index.php.swp](none)
- [DS_store](https://github.com/lijiejie/ds_store_exp) A .DS_Store file disclosure exploit. It parse .DS_Store file and download files recursively.

## 0X02 Denial Of Service
- [sloworis](https://github.com/gkbrk/slowloris)
- [slowhttptest](https://github.com/shekyan/slowhttptest)
- [LOIC](https://github.com/NewEraCracker/LOIC)

## 0X03 Scan

### Identify
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [Wafw00f](https://github.com/EnableSecurity/wafw00f)
- [Yunsee](http://www.yunsee.cn/)

### Tools For Overall Scan
- [Nmap](https://nmap.org/)
- [msscan](https://github.com/robertdavidgraham/masscan)
- [OWASP Zap](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
- [OWTF](https://owtf.github.io/#download)
- [Openvas](http://openvas.org/)
- [*Burpsuite](https://portswigger.net/burp)
- [Burpsuite extensions](https://github.com/snoopysecurity/awesome-burp-extensions/blob/master/README.md)
- [Kubernetes Files Scanning](https://kubesec.io/)
- [Nikto](https://github.com/sullo/nikto)
- [Fiddler](https://www.telerik.com/download/fiddler)
- [W3af](https://github.com/andresriancho/w3af)
- [Mantra](https://www.owasp.org/index.php/OWASP_Mantra_-_Security_Framework#tab=Downloads)
- [Discover](https://github.com/leebaird/discover)

### Useful other platform
- [XSShunter](https://xsshunter.com/app)
- [Ceye](http://ceye.io/profile)
- [Websocket client chrome extension](https://chrome.google.com/webstore/detail/simple-websocket-client/pfdhoblngboilpfeibdedpjgfnlcodoo?hl=en)


### JS API Find in Script
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

### Web Applications Scan Tools
- [Sqlmap](http://sqlmap.org/)
- [Wpscan](https://wpscan.org/)
- [Struts-scan](https://github.com/Lucifer1993/struts-scan)
- [Arachni-scanner](https://www.arachni-scanner.com/)
- [Xsstrike](https://github.com/s0md3v/XSStrike)

## 0X04 Fuzz and Password
- [Fuzzdb](https://github.com/fuzzdb-project/fuzzdb)
- [Awesome Fuzzing](https://github.com/secfigo/Awesome-Fuzzing)
- [Passwd list](https://wiki.skullsecurity.org/Passwords)hy
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [Pydictor](https://github.com/LandGrey/pydictor/blob/master/README_CN.md)

## 0X05 Password Crack
- [Hash-analyzer online](https://www.tunnelsup.com/hash-analyzer/)
- [Hash-identification online](https://www.onlinehashcrack.com/hash-identification.php)
- [Hash_type_checker online](https://md5hashing.net/hash_type_checker)
- [Hash-identifier inline kali](https://code.google.com/archive/p/hash-identifier/)
- [hashcat](https://hashcat.net/hashcat/)
- [John the Ripper](https://www.openwall.com/john/)
- [cmd5 online](http://cmd5.com/)
- [md5-decrypter online](https://hashkiller.co.uk/md5-decrypter.aspx)
- [md5hashing online](https://md5hashing.net/text-debug)
- [JWT brute force cracker written in C](https://github.com/brendan-rius/c-jwt-cracker)

## 0X06 System Vulnerability
- [Linux kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [Windows exploits](https://github.com/SecWiki/windows-kernel-exploits)
- [Tool using  public  databases to suggest windows expolits](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
- [Awesome tools to exploit Windows](https://github.com/Hack-with-Github/Windows)
- [Awesome Windows Exploitation](https://github.com/enddo/awesome-windows-exploitation)

## 0X07 Web Relevant Online Website
- [What can I use](https://caniuse.com/)
- [CSP evaluator](https://csp-evaluator.withgoogle.com/)
- [Mozilla wen documents](https://developer.mozilla.org/zh-CN/docs/Web)
- [Curesec blog](https://curesec.com/blog/)
- [JWT online](https://jwt.io/)
- [Broken browser](https://www.brokenbrowser.com/)
- [JS beautiful](http://jsbeautifier.org/)
- [JStillery](https://mindedsecurity.github.io/jstillery/)
- [PHP packagist](https://packagist.org/)

## 0X08 Existing Vulnerability Finding
- [Gathering by chybeta](https://chybeta.github.io/2017/08/19/Web-Security-Learning/)
- [0Day today](https://0day.today/)
- [CVE list](https://cve.mitre.org/cve/search_cve_list.html)
- [CNNVD](http://www.cnnvd.org.cn/)
- [CVEdetails](https://www.cvedetails.com/index.php)
- [Exploitdb](https://www.exploit-db.com/)
- [Seclists](http://seclists.org/fulldisclosure/)
- [Cxsecurity](https://cxsecurity.com/)
- [explainshell](https://www.explainshell.com/)
- [kitploit tools introduction](https://www.kitploit.com/)
- [Searchsploit](https://www.exploit-db.com/searchsploit)
- [Seebug](https://www.seebug.org/)
- [Sherlocak](https://github.com/rasta-mouse/Sherlock) PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
- [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
- [Linux Kernel Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [Next-Generation Linux Kernel Exploit Suggester](https://github.com/jondonas/linux-exploit-suggester-2)
- [Vuldb](https://vuldb.com/)

## 0X09 Cheatsheet
- [Pentestmonkey](http://pentestmonkey.net/)
- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Penetration Testing Tools Cheat Sheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
- [OWASP_Testing_Guide_v4_Table_of_Contents](https://www.owasp.org/index.php/OWASP_Testing_Guide_v4_Table_of_Contents)
- [OWASP Cheat sheat](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series)
- [sql inject cheat sheet](https://websec.ca/kb/sql_injection#MySQL_String_Concatenation)
- [Awesome WAF](https://github.com/0xInfection/Awesome-WAF)
- [Google Dorks Cheat Sheet](http://pdf.textfiles.com/security/googlehackers.pdf)
- [OWASP-Web-Checklist](https://github.com/0xRadi/OWASP-Web-Checklist)
- [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- [CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)
- [Shellcodes database for study cases](http://shell-storm.org/shellcode/)

## 0X10 Webshell And Payload
- [PHP Webshell](https://github.com/JohnTroony/php-webshells)
- [Webshell](https://github.com/tennc/webshell)
- [Payloads](https://github.com/foospidy/payloads#miscellaneous)


## 0X11 Code Review And Some Challeges
- [python](https://github.com/bit4woo/python_sec)
- [PHP-Audit-Labs](https://github.com/hongriSec/PHP-Audit-Labs)
- [Code-Audit-Challenges](https://github.com/CHYbeta/Code-Audit-Challenges)
- [Wonderkun CTF_web](https://github.com/wonderkun/CTF_web)
- [pasc2cat](https://github.com/Jyny/pasc2at)

## 0X12 Code Review Scan Tools
- [Cobra](https://github.com/WhaleShark-Team/cobra)
- [Fortify SCA](https://www.microfocus.com/en-us/products/static-code-analysis-sast/overview)
- [Phpvulhunter](https://github.com/OneSourceCat/phpvulhunter)
- [Rips](https://www.ripstech.com/)
- [VCG](https://github.com/nccgroup/VCG)
- [Bugscanner](http://tools.bugscaner.com/bugcode/)

## 0X13 Frameworks and Components POC
- [CMS-Hunter](https://github.com/SecWiki/CMS-Hunter)
- [PHP-code-audit](https://github.com/jiangsir404/PHP-code-audit)
- [POC-Collect](https://github.com/Mr5m1th/POC-Collect)


## 0X14 Malicious File Detection
- [VirSCAN.org ](http://www.virscan.org)is a FREE on-line scan service, which checks uploaded files for malware, using antivirus engines, indicated in the VirSCAN list 
- [Oletools](https://github.com/decalage2/oletools) is a package of python tools to analyze Microsoft OLE2 files(also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging. 

## 0X15 Port Foward
- [FRP](https://github.com/fatedier/frp/releases)   
- [localtunnel](https://localtunnel.github.io/www/)  
- [Ngrok](https://github.com/inconshreveable/ngrok)  
- [FRP](https://github.com/fatedier/frp)  
- [EarthWorm](http://rootkiter.com/EarthWorm/)is a portable network penetration tool with two core functions of SOCKS v5 service erection and port forwarding, which can complete network penetration in complex network environment. 
- [ReGeorg](https://github.com/sensepost/reGeorg)  
- [Proxychains](https://github.com/haad/proxychains)

## 0X16 Backdoor
- [cymothoa](https://github.com/jorik041/cymothoa) is a stealth backdooring tool, that inject backdoor’s shellcode into an existing process. The tool uses the ptrace library (available on nearly all * nix), to manipulate processes and infect them.
- [The backdoor factory](https://github.com/secretsquirrel/the-backdoor-factory) The goal of BDF is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state.
- [Shellter](https://github.com/r00t-3xp10it/venom/tree/master/obfuscate/shellter) is a dynamic shellcode injection tool aka dynamic PE infector. It can be used in order to inject shellcode into native Windows applications
- [RootKits List Download](https://github.com/d30sa1/RootKits-List-Download) is the list of all rootkits found so far on github and other sites.
- [veil](https://github.com/Veil-Framework/Veil) is a tool designed to generate metasploit payloads that bypass common anti-virus solutions.
- [Ixkeylog](https://github.com/dorneanu/ixkeylog/) is a X11 keylogger for Unix that basically uses xlib to interact with users keyboard. IXKeyLog will listen for certain X11 events and then trigger specific routines to handle these events.
- [SshLooter](https://github.com/mthbernardes/sshLooter) Script to steal passwords from ssh.
- [Schtasks-Backdoor](https://github.com/re4lity/Schtasks-Backdoor) is a powshell back door
- [Evilgrade](https://github.com/infobyte/evilgrade) is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates.
- [Luckystrike](https://github.com/curi0usJack/luckystrike) A PowerShell based utility for the creation of malicious Office macro documents.
- [DNS-Shell](https://github.com/sensepost/DNS-Shell) is an interactive Shell over DNS channel.
- [Icmpsh](https://github.com/inquisb/icmpsh)
- [Office cve1027-8570](https://github.com/rxwx/CVE-2017-8570)
- [CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882) 
- [Winrar cve2018-20250](https://github.com/WyAtu/CVE-2018-20250)

## 0X17 Intranet Domain Penetration
- [Termite](http://rootkiter.com/Termite/)  
- [Empire](https://github.com/EmpireProject/Empire)  is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing
- [Nishang](https://github.com/samratashok/nishang)  is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing
- [WMI(Windows Management Instrumentation)](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/about-wmi)   
- [mimikatz](https://github.com/gentilkiwi/mimikatz)  
- [mimikittenz](https://github.com/putterpanda/mimikittenz)   
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)  
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)  
- [UACME](https://github.com/hfiref0x/UACME) Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
- [PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite)  is a collection of PowerShell utilities which are great tools and resources online to accomplish most any task.
- [Impacket](https://github.com/SecureAuthCorp/impacket) is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch, as well as parsed from raw data, and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
- [Windows EXE Impacket](https://github.com/maaaaz/impacket-examples-windows)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/) is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts.
- [metasploit-framework](https://github.com/rapid7/metasploit-framework)
- [Koadic](https://github.com/zerosum0x0/koadic) is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec/) is designed to be used in testing and discovering flaws in one's own network with the aim of fixing the flaws detected.

## 0X18 Wifi Attack Relevant
- [Wifiphisher](https://github.com/wifiphisher/wifiphisher) is a rogue Access Point framework for conducting red team engagements or Wi-Fi security testing.
- [Aircrack](http://www.aircrack-ng.org) is a suite of tools for 802.11a/b/g WEP and WPA cracking. 
- [Wifite2](https://github.com/derv82/wifite2)
- [Ettercap](http://www.ettercap-project.org/) is a comprehensive suite for man in the middle attacks.
- [mdk3](https://github.com/wi-fi-analyzer/mdk3-master) is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.
- [RouterSoloit](https://github.com/threat9/routersploit)  is an open-source exploitation framework dedicated to embedded devices.
- [Fern wifi cracker](https://github.com/savio-code/fern-wifi-cracker)
- [Gerix wifi cracker 2](https://github.com/wi-fi-analyzer/gerix-wifi-cracker-2)
- [ghost-phisher](https://github.com/savio-code/ghost-phisher)
- [cowpatty](https://github.com/joswr1ght/cowpatty)
- [Pyrit](https://github.com/JPaulMora/Pyrit)
- [WiFi Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin)

## 0X19 After Penetration
- [LaZagne project](https://github.com/AlessandroZ/LaZagne) is an open source application used to retrieve lots of passwords stored on a local computer.
- [Phant0m](https://artofpwn.com/phant0m-killing-windows-event-log.html) is a PowerShell script and targets the Windows Event Log Service in Windows operating system.
- [Elsave](http://www.ibt.ku.dk/jesper/elsave/) is a tool to save and/or clear a NT event log.
- [Clearlogs](https://github.com/maldevel/clearlogs) Clear All Windows System Logs - AntiForensics
- [Nirsoft](http://www.nirsoft.net/) browser cache,password recovery,password cache......
- [NetRipper](https://github.com/NytroRST/NetRipper)  is a post exploitation tool targeting Windows systems which uses API hooking in order to intercept network traffic and encryption related functions from a low privileged user, being able to capture both plain-text traffic and encrypted traffic before encryption/after decryption.

## 0X20 MISC(Brute force,encode,decode,cipher)
- [rumkin](http://rumkin.com/tools/cipher/)
- [tomeko](http://tomeko.net/online_tools/)
- [cryptool-online](https://www.cryptool.org/de/cryptool-online)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [crackstation](https://crackstation.net/)
- [freeformatter](https://www.freeformatter.com/)
- [factordb](http://factordb.com/index.php)
- [Run Sage code online](https://sagecell.sagemath.org/)
- [Atbash cipher](https://planetcalc.com/4647/)
- [Hill cipher](https://planetcalc.com/3327/)
- [pigpen cipher](http://www.simonsingh.net/The_Black_Chamber/pigpen.html)
- [gif-extract](https://zh.bloggif.com/gif-extract)
- [fence password](https://www.qqxiuzi.cn/bianma/zhalanmima.php)
- [file hash](http://www.atool.org/file_hash.php)
- [QR code](http://jiema.wwei.cn/)
- [barcode-reader](https://online-barcode-reader.inliteresearch.com/)
- [MIME Headers Decoder](http://dogmamix.com/MimeHeadersDecoder/)
- [jsfuck](http://www.jsfuck.com/)
- [jsbrainfuck](https://www.nayuki.io/page/brainfuck-interpreter-javascript)
- [jsaaencode](http://utf-8.jp/public/aaencode.html?src=)
- [execute_malbolge_online](http://www.compileonline.com/execute_malbolge_online.php)

## 0x21 Vulnerability System
- [Vulnhub](https://www.vulnhub.com/)
- [Vulhub](https://vulhub.org/)
- [Webgoat](https://github.com/WebGoat/WebGoat)
- [Vulapps](http://vulapps.evalbug.com/)
- [bWAPP](http://www.itsecgames.com/)
- [DVWA](http://www.dvwa.co.uk/)
- [Sqli labs](https://github.com/Audi-1/sqli-labs)
- [XSS quiz](http://xss-quiz.int21h.jp/) answer:http://blog.knownsec.com/Knownsec_RD_Checklist/res/xss_quiz.txt
- [Prompt](http://prompt.ml/0) answer:https://github.com/cure53/XSSChallengeWiki/wiki/prompt.ml
- [Alert1](https://alf.nu/alert1) answer:
- [Lpeworkshop](https://github.com/sagishahar/lpeworkshop) Windows / Linux Local Privilege Escalation Workshop.

## 0x22 Learn More 
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)  is a library of simple tests that every security team can execute to test their controls. Tests are focused, have few dependencies, and are defined in a structured format that be used by automation frameworks.
- [Kanxue college](https://www.kanxue.com/chm.htm) 
- [Micro8](https://github.com/IversionBY/Micro8) 
- [Intranet_Penetration_Tips](https://github.com/Ridter/Intranet_Penetration_Tips)
- [OWASP](https://www.owasp.org/index.php/Main_Page)
- [Owesome DevsecOps](https://github.com/devsecops/awesome-devsecops)
- [Intranet Penetration Tips](https://github.com/Ridter/Intranet_Penetration_Tips)
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
- [Scanner-Box](https://github.com/We5ter/Scanners-Box)  is the toolbox of open source scanners
- [Mind Map](https://github.com/phith0n/Mind-Map)
- [Sec-chart](https://github.com/SecWiki/sec-chart)
- [Seclists](https://github.com/danielmiessler/SecLists)
- [SecurityDoucument](https://github.com/bollwarm/SecToolSet/blob/master/SecurityDoucument.md)
- [Ired Team](https://ired.team/)
- [Osstmm](http://www.isecom.org/research/osstmm.html) Open Source Security Testing Methodology Manual (OSSTMM).
- [HTML5 sec](http://html5sec.org/)
- [The-Hacker-Playbook-3-Translation](https://github.com/Snowming04/The-Hacker-Playbook-3-Translation/blob/master/PDF/%5B%E8%AF%91%5D%20%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%AE%9E%E6%88%98%E7%AC%AC%E4%B8%89%E7%89%88(%E7%BA%A2%E9%98%9F%E7%89%88)3%E6%9C%8819%E6%97%A5%E6%9B%B4%E6%96%B0.pdf)
- [APTnotes](https://github.com/kbandla/APTnotes)
- [TOOLS](https://www.t00ls.net/pytools.html)
- [Knownsec RD Checklist](http://blog.knownsec.com/Knownsec_RD_Checklist/
## standard
- [OWASP_Testing_Guide_v4_Table_of_Contents](https://www.owasp.org/index.php/OWASP_Testing_Guide_v4_Table_of_Contents)
- [PCI-DSS](https://www.pcisecuritystandards.org/minisite/en/pci-dss-v3-0.php)


