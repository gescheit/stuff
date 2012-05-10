# -*- coding: utf-8 -*-
'''
Created on 08.04.2012

@author: gescheit
'''
from scapy.all import *
import sys
import random
import time
import IPy
from threading import Thread
import os

dst = "2a02:6b8::1000:1000" #ipv6.yandex.ru
#dst = "77.88.16.67"
dport = 12345
my_payload = "GET /testdata HTTP/1.0\r\n\r\n"
#my_payload = "GET /?ncrnd=1394397669 HTTP/1.1\r\nHost:ipv6.yandex.ru\r\n\r\n"
mss = 9000

dst_type = IPy.IP(dst).version()
if dst_type == 4:
    ip = IP(dst=dst, flags="DF")
elif dst_type == 6:
    ip = IPv6(dst=dst)

soport = random.randint(1024, 65000)
packets = []


def arp_monitor_callback(pkt):
    packets.append(pkt)
    #if ARP in pkt and pkt[ARP].op in (1, 2): #who-has or is-at
    #    return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
#запускаем снифер
sfilter = "tcp and port %s" % soport


def snifff():
    sniff(prn=arp_monitor_callback, filter=sfilter, store=0)

t = Thread(target=snifff)
t.start()

SYN = TCP(dport=dport, flags="S", options=[("MSS", mss)], sport=soport, seq=RandNum(100, 150), window=18000)
ans, unans = sr(ip / SYN)

print "SEND:", ans[0][0].show()
print "RCV:", ans[0][1].show()

#my_payload = "GET /javascripts/jquery.fcbkcomplete.js?1322596141 HTTP/1.0\r\n\r\n"
#my_payload = "GET /jquery/1.6.2/jquery.min.js HTTP/1.0\r\nHost: yandex.st\r\n\r\n"
#my_payload = "GET /testdata HTTP/1.0\r\n\r\n"

#просто подтверждает SYN/ACK
ACK = TCP(dport=dport, flags="A", sport=soport, ack=ans[0][1].seq + 1, seq=ans[0][1].ack)
send(ip / ACK)
#rint "SEND:", ans[0][0].show()
#nt "RCV:", ans[0][1].show()


#делаем запрос
ACK = TCP(dport=dport, flags="PA", sport=soport, ack=ans[0][1].seq + 1, seq=ans[0][1].ack)
ans, unans = sr(ip / ACK / my_payload, retry=0, timeout=3)
print "SEND:", ans[0][0].show()
print "RCV:", ans[0][1].show()

if dst_type == 4:
    tcp_payload_size = packets[-1][IP].len - packets[-1][TCP].dataofs * 8
elif dst_type == 6:
    tcp_payload_size = packets[-1][IPv6].plen - packets[-1][TCP].dataofs * 8

#подтверждание? хрен, надо payload tcp, который во втором пакете на предыдущий запрос
ACK = TCP(dport=dport, flags="A", sport=soport, ack=ans[0][1].seq + tcp_payload_size, seq=ans[0][1].ack)
ans, unans = sr(ip / ACK, retry=0, timeout=1)
#print "SEND:", ans[0][0].show()
#print "RCV:", ans[0][1].show()

os._exit(1)

#TOOBIG = ICMPv6PacketTooBig(mtu=1001)
#ans2, unans2 = sr(ip / TOOBIG / ans[0][1], retry=0, timeout=3)
#print "SEND:", ans2[0][0].show()
#print "RCV:", ans2[0][1].show()

TOOBIG = ICMP(type=3, code=4, unused=200)
ans2, unans2 = sr(ip / TOOBIG / ans[0][1], retry=0, timeout=3)
if ans2:
    print "SEND:", ans2[0][0].show()
    print "RCV:", ans2[0][1].show()


ACK = TCP(dport=dport, flags="A+DF", sport=soport, ack=ans[0][1].seq + 1, seq=ans[0][1].ack)
ans, unans = sr(ip / ACK, retry=0, timeout=3)
print "SEND:", ans[0][0].show()
print "RCV:", ans[0][1].show()




#time.sleep(2)
FIN = TCP(dport=80, flags="F", sport=soport, ack=ans[0][1].seq + 1, seq=ans[0][1].ack)
ans, unans = sr(ip / FIN)
print "SEND:", ans[0][0].show()
print "RCV:", ans[0][1].show()

