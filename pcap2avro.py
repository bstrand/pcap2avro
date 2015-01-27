__author__ = 'bstrand'

import sys
import socket
import argparse
import dpkt

import avro.schema
from avro.datafile import DataFileWriter
from avro.io import DatumWriter

from kafka import *

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
    infile = "/Users/bstrand/insight/pcaps/bigPcap/5gb-tcp-connection.pcap"
    outfile = "/Users/bstrand/insight/pcaps/bigPcap/5gb-tcp-connection.avro"

    try:
        schema = avro.schema.parse(open("/Users/bstrand/insight/pcap2avro/tcp.avsc").read())
    except:
        print "Failed to parse Avro schema file"
        sys.exit()

    try:
        f = open(infile, 'rb')
    except:
        print "Failed to open " + infile
        sys.exit()

    try:
        pcap = dpkt.pcap.Reader(f)
    except:
        print "Failed to parse " + infile
        sys.exit()

    mykafka = KafkaClient("bstrand-kafka01:9092")
    producer = SimpleProducer(mykafka)


    try:
        writer = DataFileWriter(open(outfile, "w"), DatumWriter(), schema)
    except:
        print "Failed to open Avro output file %s" % outfile
        sys.exit()

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
        except:
            continue

        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        # TODO Temporary limitation to IPv4 TCP packets
        if (ip.p != 6):
            continue

        tcp = ip.data
        sport = str(tcp.sport)
        dport = str(tcp.dport)

        proto = proto_id_to_name(ip.p)
        packetlength = ip.len-ip.hl*4

        pktStr =  "%s | %s : %d -> %s : %d, len: %d, seq: %d, ack: %d, flags 0x%02x, win %d, proto: %s" \
              % (ts, src, tcp.sport, dst, tcp.dport, packetlength, tcp.seq, tcp.ack, tcp.flags, tcp.win, proto)
        print pktStr

        writer.append({
            "timestamp": ts,
            "ip_TTL": ip.ttl,
            "ip_protocol": proto,
            "ip_src": src,
            "ip_dst": dst,
            "ip_pkt_len": ip.len,
            "tcp_src_port": tcp.sport,
            "tcp_dst_port": tcp.dport,
            "tcp_seq_num": tcp.seq,
            "tcp_ack_num": tcp.ack,
            "tcp_flags": tcp.flags,
            "tcp_window": tcp.win
        })

        producer.send_messages("pcap_test", pktStr)

    writer.close()


if __name__ == '__main__':
    main()