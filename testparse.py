__author__ = 'bstrand'

import sys
import socket
import argparse
import dpkt
import avro

def parse_args():
    parser = argparse.ArgumentParser(description='pcap2avro - Serialize IP packets from pcap files into Avro format')
    parser.add_argument('pcap_files', metavar='file', nargs='+',
                        help='pcap file(s) to serialize')
    parser.add_argument('output_file', metavar='out', nargs='+',
                        help='Output file; defaults to <source filename>.avro')
    parser.add_argument("--debug", help="Write debug output.", action="store_true")
    args = parser.parse_args()
    if args.debug:
        print "Args parsed."
        print "Input files: "
        for filename in args.pcap_files:
            print "\t", filename
    return args


def proto_has_port(p):
    return p==6 or p==17

def proto_id_to_name(p):
    if p==6:
        return 'tcp'
    elif p == 17:
        return 'udp'
    else:
        return '???'

def main():
    # args = parse_args()
    filename = "/Users/bstrand/insight/pcaps/live/live-20150123.pcap"

    try:
        f = open(filename, 'rb')
    except:
        print "Failed to open " + filename
        sys.exit()

    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print "Failed to parse " + filename
        sys.exit()

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                print eth.type
                continue
        except:
            continue

        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dest = socket.inet_ntoa(ip.dst)
        if proto_has_port(ip.p):
            sport = str(ip.data.sport)
            dport = str(ip.data.dport)
        proto = proto_id_to_name(ip.p)
        packetlength = ip.len-ip.hl*4

        print "%s:%s -> %s:%s, %s, %d" % (src, sport, dest, dport, proto, packetlength)

if __name__ == '__main__':
    main()