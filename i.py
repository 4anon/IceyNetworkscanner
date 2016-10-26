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
closed = 0
 
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
                    print "[*] %d open" % port
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

    conf.verb = 0
    start_time = time.time()
    ports = range(1, 1024)
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

    return choice

print'''

  ___               _  _     _                  _     ___                            
 |_ _|__ ___ _  _  | \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _ 
  | |/ _/ -_) || | | .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___\__\___|\_, | |_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|  
             |__/                                                                   

Installer
'''

choices = OrderedDict((
    ('1', ('Host Discovery', discover_hosts)),
    ('2', ('Port Scanning', scan_ports)),
    ('3', ('Misc', misc)),
    ('4', ('Exit', exit))
))

while True:
    choice = get_user_choice(choices)
    print 'you chose %s (type: %s)' % (choice, type(choice))
    choices[choice][1]()
