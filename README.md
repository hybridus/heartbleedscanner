# Heartbleed Scanner

Network Scanner for OpenSSL Memory Leak (CVE-2014-0160) 

-t parameter to optimize the timeout in seconds.
-f parameter to log the memleak of vulnerable systems.
-n parameter to scan entire network.
-i parameter to scan from a list file. Useful if you already have targets.
-r parameter to randomize the IP addresses to avoid linear scanning.
-s parameter to exploit services that requires plaintext command to start SSL/TLS (HTTPS/SMTP/POP3/IMAP)

Sample usage : 
To scan your local 192.168.1.0/24 network for HB vulnerability (https/443) and save the leaks into a file:
  python heartbleedscan.py -n 192.168.1.0/24 -f localscan.txt -r 
To scan the same network against SMTP Over SSL/TLS and randomize the IP addresses
  python heartbleedscan.py -n 192.168.1.0/24 -p 25 -s SMTP -r
If you already have a target list which you created by using nmap/zmap
  python heartbleedscan.py -i targetlist.txt 

Enjoy.

-bc
