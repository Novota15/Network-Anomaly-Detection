# Network-Anomaly-Detection
Programmtically analyzing trace data to detect suspicious behavior.

### Project Overview

This is a python script that analyzes network trace data to detect suspicious behavior. Specifically, it gathers port scanning suspects.

Port scanning is a technique used to find network hosts that have services listening on one or more target ports. It can be used offensively to locate vulnerable systems in preparation for an attack, or defensively for research or network administration. In one port scan technique, known as a SYN scan, the scanner sents TCP SYN packets (the first packet in the TCP handshake) and watches for hosts that respond with SYN+ACK packets (the second handshake step).

Since most hosts are not prepared to receive connections on any given port, typically, during a port scan, a much smaller number of hosts will respond with SYN+ACK packets than originally received by SYN packets. By observing this effect in a packet trace, you can identify source addresses that may be attempting a port scan.

This program analyzes a PCAP file (a network capture file created through wireshark) in order to detect possible SYN scans. The program takes one argument, the name of the PCAP file to be analyzed:

```python3 detector.py capture.pcap```

The output is the set of IP addresses that sent more than 3 times as many SYN packets as the numer of SYN+ACK packets they received. It silently ignores packets that are malformed or that are not using Ethernet, IP, and TCP.

A sample PCAP file captured from a real network was used for the testing of this project and can be found here: ftp://ftp.bro-ids.org/enterprise-traces/hdr-traces05/lbl-internal.20041004-1305.port002.dump.anon. The following suspects were found when analyzing this pcap file:

```
128.3.23.2
128.3.23.5
128.3.23.117
128.3.23.158
128.3.164.248
128.3.164.249
```
