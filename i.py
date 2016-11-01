#!/usr/bin/python

import time
import Queue
import threading
import logging
import os
import sys
from collections import OrderedDict
from subprocess import check_output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#Getting Useful information automatically
route = check_output(['route'])
gateaway,iface= (route.split()[i] for i in (19,20) )
errorhandlingmessage = 'unknown port'
closed = 0
portlist = { 80: 'webserver'}  
class Scanner(threading.Thread):
    """ Scanner Thread class """
    def __init__(self, queue, lock, ip):
        super(Scanner, self).__init__()
        self.queue = queue
        self.lock = lock
        self.ip = ip

    def run(self):
        global closed
        src_port = RandShort()
        port = self.queue.get()
        p = IP(dst=self.ip)/TCP(sport=src_port, dport=port, flags='S')
        resp = sr1(p, timeout=2)
        if resp is None:
            with lock:
                closed += 1 
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=self.ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
                with self.lock: 
                    print "[*] %d %s open" % (port, portlist.get(port, errorhandlingmessage))
            elif resp.getlayer(TCP).flags == 0x14:
                with self.lock:
                    closed += 1
        self.queue.task_done()

                                                                                

def is_up(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10, verbose=0)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True

def discover_hosts():
    print "[*] You did choose Host Discovery"

    print
    print
    print
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(iface) + "/24"),timeout=2, verbose = 0)
    ans.summary(lambda (s,r): r.sprintf("[+]You did find: " + "[*]IP: %ARP.psrc% [*]MAC: %Ether.src% "))
    print
    print

def scan_ports():
    print
    print
    print "[*] You did choose Port Scanning"
    ip = raw_input("[+]Please enter your Target > ")
    minport = raw_input("[+] Please enter the minimum of port to scan, Enter to keep default range > ")
    maxport = raw_input("[+] Please enter the maximum port to scan, Enter to keep default range\n  tip: dont do to much, then it takes to much time > ")
    empty = ''
    try:
        if minport and maxport != 0:
            ports = range(int(minport), int(maxport))
        elif minport and maxport == 0:
            ports = range(1, 1024)
        else:
            print "[~]Something went wrong"
            sys.exit()
    except:
        print "[~]Error in the File"
        print "[*] Exiting"
        sys.exit()
    conf.verb = 0
    start_time = time.time()
    lock = threading.Lock()
    queue = Queue.Queue()
    if is_up(ip):
        print "Host %s is up, start scanning" % ip
        for port in ports:
            queue.put(port)
            scan = Scanner(queue, lock, ip)
            scan.start()
        queue.join()
        duration = time.time()-start_time
        print "%s Scan Completed in %fs" % (ip, duration)
        print "%d closed ports in %d total port scanned" % (closed, len(ports))

def misc():
    print
    print
    print
    print "[*] You did choose misc."
    print

def exit():
    print "[~] Exiting"
    sys.exit()


def get_user_choice(choices):
    choice = None
    while choice not in choices:
        for i, (name, _) in choices.items():
            print '%s. %s' % (i, name)
        choice = raw_input('> ').strip()
        if choice not in choices:
            print "[~]%s is not a valid Command " % choice
            print 
            print

    return choice

print'''

  ___               _  _     _                  _     ___                            
 |_ _|__ ___ _  _  | \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _ 
  | |/ _/ -_) || | | .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___\__\___|\_, | |_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|  
             |__/                                                                   


'''

choices = OrderedDict((
    ('1', ('Host Discovery', discover_hosts)),
    ('2', ('Port Scanning', scan_ports)),
    ('3', ('Misc', misc)),
    ('4', ('Exit', exit))

))

while True:
    choice = get_user_choice(choices)
    choices[choice][1]()
