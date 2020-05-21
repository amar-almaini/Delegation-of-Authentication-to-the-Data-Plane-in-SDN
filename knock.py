#! /usr/bin/env python
from scapy.all import *
send(IP(dst="10.0.3.10")/TCP(dport=5100))
send(IP(dst="10.0.3.10")/TCP(dport=5150))
send(IP(dst="10.0.3.10")/TCP(dport=5155))
