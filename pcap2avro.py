__author__ = 'bstrand'

import sys
import socket
import argparse
import dpkt
from datetime import datetime

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
    if p==6:
        return 'tcp'
    elif p == 17:
        return 'udp'
    else:
        return '???'


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

   #producer = init_kafka(kafka_endpoint)

    try:
        writer = DataFileWriter(open(avro_output_file, "w"), DatumWriter(), schema)
    except Exception as e:
        print "Failed to open Avro output file %s" % avro_output_file
        print e
        sys.exit()

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
        except:
            continue

        ip = eth.data
        # TODO limited to IPv4 TCP packets
        if (ip.p != 6):
            continue
        tcp = ip.data

        if(args.debug):
            # Do some conversions now
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            proto = proto_id_to_name(ip.p)
            packetlength = ip.len-ip.hl*4

            # Debug output
            humanTS = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
            pktStr =  "%s | %s  %s : %d -> %s : %d, len: %d, seq: %d, ack: %d, flags 0x%02x, win %d" \
                  % (humanTS, proto.upper(), src, tcp.sport, dst, tcp.dport, packetlength, tcp.seq, tcp.ack, tcp.flags, tcp.win )
            print pktStr

        tcp_data = {}
        tcp_data['src_port'] = tcp.sport
        tcp_data['dst_port'] = tcp.dport
        tcp_data['seq_num'] = tcp.seq
        tcp_data['ack_num'] = tcp.ack
        tcp_data['flags'] = tcp.flags
        tcp_data['window'] = tcp.win

        writer.append({
            "ts": ts,

            "ttl": ip.ttl,
            "proto_id": ip.p,
            "src_addr": socket.inet_ntoa(ip.src),
            "dst_addr": socket.inet_ntoa(ip.dst),
            "length": ip.len,

            "tcp": tcp_data
        })

        #producer.send_messages("pcap_bin_test", pktStr)

    writer.close()

def proc_old_tcp(pcap_file):
    # args = parse_args()
    #pcap_file = "/Users/bstrand/insight/data/pcaps/ppa-capture-files/http.cap"
    avro_schema_file = "/Users/bstrand/insight/pcap2avro/schema/tcp.avsc"
    kafka_endpoint = "kafka01.steepbeach.net:6667"
    avro_output_file = pcap_file + '.avro'

    # Initialize
    schema = read_avro_schema(avro_schema_file)

    pcap = read_pcap(pcap_file)

   #producer = init_kafka(kafka_endpoint)


    try:
        writer = DataFileWriter(open(avro_output_file, "w"), DatumWriter(), schema)
    except:
        print "Failed to open Avro output file %s" % avro_output_file
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
        # TODO limited to IPv4 TCP packets
        if (ip.p != 6):
            continue

        tcp = ip.data
        sport = str(tcp.sport)
        dport = str(tcp.dport)

        proto = proto_id_to_name(ip.p)
        packetlength = ip.len-ip.hl*4

        humanTS = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

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