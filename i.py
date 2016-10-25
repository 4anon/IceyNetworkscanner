import logging
import os
from subprocess import check_output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#Getting Useful information automatically
route = check_output(['route'])
gateaway,iface= (route.split()[i] for i in (19,20) )

print "1. Host Discovery - 1"
print "2. Port Scanning - 2"
print "3. Misc. - 3"
print "4. Exit - 4"
while True:
	choice = raw_input("> ")
	if choice == "1":
		print "you did choose Host Discovery"
		try:
			ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(iface) + "/24"),timeout=2, verbose = 0)
			ans.summary(lambda (s,r): r.sprintf("[+]You did find: " + "[*]IP: %ARP.psrc% [*]MAC: %Ether.src% "))
		except:
			print "Host Discovery Failed"
			print "1. Host Discovery - 1"
			print "2. Port Scanning - 2"
			print "3. Misc. - 3"
			print "4. Exit - 4"
	elif choice == "2":
		print "you did choose Port Scanning"
		print "1. Host Discovery - 1"
		print "2. Port Scanning - 2"
		print "3. Misc. - 3"
		print "4. Exit - 4"
	elif choice == "3":
		print "you did choose misc."
	elif choice == "4":
		print "[+] Exiting"
		break
	else:
		print choice + " is not a valid command"
		
