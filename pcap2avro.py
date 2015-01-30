__author__ = 'bstrand'

import sys
import socket
import argparse
import dpkt
import time

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


def init_kafka(endpoint):
    mykafka = KafkaClient(endpoint)
    return SimpleProducer(mykafka)


def read_pcap(infile):
    try:
        f = open(infile, 'rb')
    except:
        print "Failed to open " + infile
        sys.exit()
    try:
        pcap = dpkt.pcap.Reader(f)
    except ValueError as ve:
        print "Failed to parse " + infile
        print ve
        sys.exit()
    except:
        print "Failed to parse " + infile
        sys.exit()

    return pcap


def read_avro_schema(fpath):
    try:
        schema = avro.schema.parse(open(fpath).read())
    except:
        print "Failed to parse Avro schema file " + fpath
        sys.exit()
    return schema


def main():
    # Config
    # args = parse_args()
    #pcap_file = "/Users/bstrand/insight/pcaps/hptcp.pcap"
    pcap_file = "/Users/bstrand/insight/pcaps/ppa-capture-files/http.cap"
    avro_schema_file = "/Users/bstrand/insight/pcap2avro/tcp.avsc"
    kafka_endpoint = "bstrand-kafka01:9092"
    test_avro_output = pcap_file + '.avro'

    # Initialize
    schema = read_avro_schema(avro_schema_file)

    pcap = read_pcap(pcap_file)

   #producer = init_kafka(kafka_endpoint)


    try:
        writer = DataFileWriter(open(test_avro_output, "w"), DatumWriter(), schema)
    except:
        print "Failed to open Avro output file %s" % test_avro_output
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

        humanTS = '%s.%03d' % (time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts)), 0)

        pktStr =  "%s | %s  %s : %d -> %s : %d, len: %d, seq: %d, ack: %d, flags 0x%02x, win %d" \
              % (humanTS, proto.upper(), src, tcp.sport, dst, tcp.dport, packetlength, tcp.seq, tcp.ack, tcp.flags, tcp.win )
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

        #producer.send_messages("pcap_bin_test", pktStr)

    writer.close()


if __name__ == '__main__':
    main()