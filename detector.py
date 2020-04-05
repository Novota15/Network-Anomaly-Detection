import dpkt
import socket
from sys import argv

def get_suspects(filename):
    try:
        pcap = dpkt.pcap.Reader(open(filename, 'rb'))
    except:
        print("Can't open pcap:", filename)
        return
    
    suspects = {}
    # scan through pcap
    for ts, buf in pcap:
        # ignore malformed packets
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except (dpkt.dpkt.UnpackError, IndexError):
            continue

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            # skip packets that are not IP
            continue

        ip = eth.data
        if not ip:
            # packet must include IP protocol to get TCP
            continue

        if ip.p != dpkt.ip.IP_PROTO_TCP:
            # skip packets that are not TCP
            continue
        tcp = ip.data
        
        # get source and destination IPs
        src_IP = socket.inet_ntoa(ip.src)
        dst_IP = socket.inet_ntoa(ip.dst)

        # append possible suspects
        # SYN request
        if ((tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)):
            if src_IP not in suspects:
                suspects[src_IP] = {'SYN': 0, 'SYN-ACK': 0} # initialize
            suspects[src_IP]['SYN'] += 1
        # SYN-ACK reply
        elif ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
            if dst_IP not in suspects:
                suspects[dst_IP] = {'SYN': 0, 'SYN-ACK': 0} # initialize
            suspects[dst_IP]['SYN-ACK'] += 1

    return suspects       

def prune_suspects(suspects):
    # delete suspects based on ratio of SYNs to SYN-ACKs (3:1)
    for s in list(suspects.keys()):
       if suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * 3):
           del suspects[s]
    return suspects

def detector(filepath):
    suspects = get_suspects(filepath)
    suspects = prune_suspects(suspects)
    for s in suspects.keys():
        print(s)
    return
    
if len(argv) == 2:
    detector(argv[1])
else:
    print('Enter pcap file path as an argument')