# Heartbleed Scanner

Network Scanner for OpenSSL Memory Leak (CVE-2014-0160) 

-t parameter to optimize the timeout in seconds.<br/>
-f parameter to log the memleak of vulnerable systems.<br/>
-n parameter to scan entire network.<br/>
-i parameter to scan from a list file. Useful if you already have targets.<br/>
-r parameter to randomize the IP addresses to avoid linear scanning.<br/>
-s parameter to exploit services that requires plaintext command to start SSL/TLS (HTTPS/SMTP/POP3/IMAP)<br/>
<br/><br/>
Sample usage :<br/> 
To scan your local 192.168.1.0/24 network for HB vulnerability (https/443) and save the leaks into a file:<br/>
  python heartbleedscan.py -n 192.168.1.0/24 -f localscan.txt -r <br/>
To scan the same network against SMTP Over SSL/TLS and randomize the IP addresses<br/>
  python heartbleedscan.py -n 192.168.1.0/24 -p 25 -s SMTP -r<br/>
If you already have a target list which you created by using nmap/zmap<br/>
  python heartbleedscan.py -i targetlist.txt <br/>
<br/><br/>
Enjoy.<br/><br/>

-bc
