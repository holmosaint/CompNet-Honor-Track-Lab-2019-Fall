import argparse
import os
import sys
import time
from datetime import datetime
import pickle

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def printable_timestamp(ts):
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%SZ')

def pickle_pcap(args):
    pcap_file_in, pickle_file_out = args.pcap, args.out

    print('Opening {}...'.format(pcap_file_in))
    
    if not os.path.isfile(pcap_file_in):
        print('"{}" does not exist'.format(pcap_file_in), file=sys.stderr)
        sys.exit(-1)

    count = 0
    interesting_packet_count = 0

    # List of interesting packets, will finally be pickled.
    # Each element of the list is a dictionary that contains fields of interest
    # from the packet.
    packets_for_analysis = list()

    for (pkt_data, pkt_metadata, ) in RawPcapReader(pcap_file_in):
        count += 1

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        # print(pkt_metadata)
        interesting_packet_count += 1
        if interesting_packet_count == 1:
            first_pkt_timestamp = pkt_metadata.sec
        
        last_pkt_timestamp = pkt_metadata.sec

        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp

        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            return False

        tcp_pkt = ip_pkt[TCP]

        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        # Look for the 'Window Scale' TCP option if this is a SYN or SYN-ACK
        # packet.
        """if 'S' in str(tcp_pkt.flags):
            for (opt_name, opt_value,) in tcp_pkt.options:
                if opt_name == 'WScale':
                    window_scale = opt_value
                    break"""

        # Create a dictionary and populate it with data that we'll need in the
        # analysis phase.
        
        pkt_data = {}
        pkt_data['source_IP'] = ip_pkt.src
        pkt_data['dest_IP'] = ip_pkt.dst
        pkt_data['source_TCP_Port'] = tcp_pkt.sport
        pkt_data['dest_TCP_Port'] = tcp_pkt.dport
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp
        pkt_data['tcp_flags'] = str(tcp_pkt.flags)
        pkt_data['seqno'] = tcp_pkt.seq
        pkt_data['ackno'] = tcp_pkt.ack
        pkt_data['tcp_payload_len'] = int(tcp_payload_len)
        # pkt_data['window'] = tcp_pkt.window << window_scale

        packets_for_analysis.append(pkt_data)

    print('{} contains {} packets({} interesting)'.format(pcap_file_in, count, interesting_packet_count))
    
    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
        pickle.dump(packets_for_analysis, pickle_fd)
    print('done.')

def analyze_pickle(args):
    pickle_file_in = args.pk

    if not os.path.isfile(pickle_file_in):
        print('"{}" does not exist'.format(pickle_file_in), file=sys.stderr)
        sys.exit(-1)    

    packets_for_analysis = []
    
    with open(pickle_file_in, 'rb') as pickle_fd:
        packets_for_analysis = pickle.load(pickle_fd)
        
    # Print format string
    fmt = ('[source:{srcIP}:{srcPort}] [dest:{destIP}:{destPort}] {ts}s {flag:<3s} seq={seq:<8d} '
           'ack={ack:<8d} len={len:<6d}')

    for pkt_data in packets_for_analysis:
        print(fmt.format(srcIP = pkt_data['source_IP'],
                         destIP = pkt_data['dest_IP'], 
                         srcPort = pkt_data['source_TCP_Port'],
                         destPort = pkt_data['dest_TCP_Port'],
                         ts = printable_timestamp(pkt_data['relative_timestamp']),
                         flag = pkt_data['tcp_flags'],
                         seq = pkt_data['seqno'],
                         ack = pkt_data['ackno'],
                         len = int(pkt_data['tcp_payload_len'])))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PCAP parser')
    sub_parser = parser.add_subparsers(title='subcommands', description='valid subcommands')

    parser_pickle = sub_parser.add_parser('pickle')
    parser_pickle.add_argument('--pcap', metavar='pcap file name', help='pcap file to parse')
    parser_pickle.add_argument('--out', metavar='output pickle file name', help='pickle file to store the metadata')
    parser_pickle.set_defaults(func=pickle_pcap)

    parser_analyze = sub_parser.add_parser('analyze')
    parser_analyze.add_argument('--pk', metavar='input pickle file name', help='pickle file to analyze')
    parser_analyze.set_defaults(func=analyze_pickle)
    
    args = parser.parse_args()

    args.func(args)

