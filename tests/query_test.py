#!/usr/bin/env python3
import ns_lame_detector
l=ns_lame_detector.LAME()
print(l.dns_query(query='www.infoblox.com', qtype='A'))
print(l.dns_query(query='google.com', qtype='NS', nameserver='8.8.8.8'))
print(l.dns_query(query='google.com', qtype='NS', nameserver='192.43.172.30'))