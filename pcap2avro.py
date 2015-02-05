__author__ = 'bstrand'

# TODO convert to class
# TODO refactor for config to replace hardcoded settings

import sys
import socket
import argparse
import dpkt
from datetime import datetime
from collections import Counter

import avro.schema
from avro.datafile import DataFileWriter
from avro.io import DatumWriter

from kafka import *

args = []

def parse_args():
    parser = argparse.ArgumentParser(description='pcap2avro - Serialize IP packets from pcap files into Avro format')
    parser.add_argument('pcap_files', metavar='file', nargs='+',
                        help='pcap files to     serialize into Avro')
    parser.add_argument('-o', '--out', metavar='output file', nargs='?',
                        help='Write output to this file')
    parser.add_argument('-k', '--kafka', metavar='kafka file', nargs='?',
                        help='Publish messages to Kafka with specified config')
    parser.add_argument('-s', '--schema', metavar='Avro schema definition', nargs='?',
                        help='Publish messages to Kafka with specified config')
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
    if p==2:
        return 'ICMP'
    elif p==6:
        return 'TCP'
    elif p == 17:
        return 'UDP'
    else:
        return 'other'


def init_kafka(endpoint):
    my_kafka = KafkaClient(endpoint)
    return SimpleProducer(my_kafka)


def read_pcap(infile):
    try:
        f = open(infile, 'rb')
    except Exception as e:
        print "Failed to open " + infile
        print e
        sys.exit()
    try:
        pcap = dpkt.pcap.Reader(f)
    except Exception as e:
        print "Failed to parse " + infile
        print e
        sys.exit()

    return pcap


def read_avro_schema(fpath):
    try:
        schema = avro.schema.parse(open(fpath).read())
    except Exception as e:
        print "Failed to parse Avro schema file " + fpath
        print e
        sys.exit()
    return schema


def main():
    global args
    args = parse_args()
    for f in args.pcap_files:
        ingest_file(f)

def ingest_file(pcap_file):
    avro_schema_file = "./schema/ip.avsc"
    #kafka_endpoint = "kafka01.steepbeach.net:6667"
    avro_output_file = pcap_file + '.avro'

    # Initialize
    schema = read_avro_schema(avro_schema_file)
    pcap = read_pcap(pcap_file)
    packet_count = Counter(['total','IP','IPv6','dropped','TCP','UDP','ICMP','error'])

   #producer = init_kafka(kafka_endpoint)

    try:
        writer = DataFileWriter(open(avro_output_file, "w"), DatumWriter(), schema)
    except Exception as e:
        print "Failed to open Avro output file %s" % avro_output_file
        print e
        sys.exit()

    for ts, buf in pcap:
        packet_count['total'] += 1

        # Initial packet parse, drop anything but IP frames
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                packet_count['dropped'] += 1
                continue
        except:
            packet_count['error'] += 1
            continue

        # Parse IP packet; drop anything IPv4/{ICMP,TCP,UDP}
        ip = eth.data
        if (ip.p not in [2,6,17]):
            if (ip.p == 41):
                packet_count['IPv6'] += 1
            packet_count['dropped'] += 1
            continue
        packet_count['IP'] += 1

        # Init protocol data
        tcp_data = None
        icmp_data = None
        udp_data = None

        if(args.debug):
            # Do some conversions now
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            proto = proto_id_to_name(ip.p)
            packetlength = ip.len-ip.hl*4
            humanTS = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

        if (ip.p == 2):
            packet_count['ICMP'] += 1
            # TODO
        elif (ip.p == 6):
            packet_count['TCP'] += 1
            tcp = ip.data

            if(args.debug):
                pktStr =  "%d | %s | %s | %s : %d -> %s : %d, len: %d, seq: %d, ack: %d, flags 0x%02x, win %d" \
                      % (packet_count['total'], humanTS, proto, src, tcp.sport, dst, tcp.dport, packetlength, tcp.seq, tcp.ack, tcp.flags, tcp.win )
                print pktStr

            tcp_data = {}
            tcp_data['src_port'] = tcp.sport
            tcp_data['dst_port'] = tcp.dport
            tcp_data['seq_num']  = tcp.seq
            tcp_data['ack_num']  = tcp.ack
            tcp_data['flags']    = tcp.flags
            tcp_data['window']   = tcp.win

        elif (ip.p == 17):
            packet_count['UDP'] += 1
            udp = ip.data

            if(args.debug):
                pktStr =  "%d | %s | %s | %s : %d -> %s : %d, len: %d" \
                      % (packet_count['total'], humanTS, proto, src, udp.sport, dst, udp.dport, udp.ulen)
                print pktStr

            udp_data = {}
            udp_data['src_port'] = udp.sport
            udp_data['dst_port'] = udp.dport
            udp_data['length']   = udp.ulen

        writer.append({
            "ts": ts,

            "ttl": ip.ttl,
            "proto_id": ip.p,
            "src_addr": socket.inet_ntoa(ip.src),
            "dst_addr": socket.inet_ntoa(ip.dst),
            "length": ip.len,

            "tcp":  tcp_data,
            "udp":  udp_data,
            "icmp": icmp_data
        })

        #producer.send_messages("pcap_bin_test", pktStr)

    writer.close()

if __name__ == '__main__':
    main()