
import time
import os
import sys
import platform

osversion = platform.system()

pyversion = sys.version
pyversion.split()
abra = pyversion[0:3]

print'''

  ___               _  _     _                  _     ___                            
 |_ _|__ ___ _  _  | \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _ 
  | |/ _/ -_) || | | .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___\__\___|\_, | |_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|  
             |__/                                                                   

Installer
'''

if osversion == 'Linux' or 'linux':
	print '[*] WOOP WOOP!'
	print '[*]You got Linux'
	print '[*] Lets see if you got python 2.7'
	if abra == '2.7':
		print '[++] You got it the right version'
		try:
			import logging
			logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
			import scapy.all
			print '[*] Scapy got imported'
			print '[*] Everything Done'
			print '[*] Exiting...'


		except:
			os.popen('pip install scapy')
			print '[+] Installed Scapy Sucessfully'
			print '[*]Exiting...'
	else:
		'[*] Sorry but this python version is not recommended \n go install 2.7 instead'		
			

elif osversion == 'Windows' or 'Windows':
	print '[~] Go shoot yourself'
	print '[*] Icey Network Scanner is made for Linux'
	print '[*] Exiting...'
	time.sleep(6)
	sys.exit()
	


else:
	print '[~] Something must have gone wrong'
	print '[*] Exiting'




	




	
