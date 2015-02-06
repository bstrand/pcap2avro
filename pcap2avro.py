__author__ = 'bstrand'

# TODO convert to class
# TODO Refactor protocol parsing into methods
# TODO refactor for config to replace hardcoded settings

import sys
import socket
import argparse
import dpkt
import io
#import cStringIO
from datetime import datetime
from collections import Counter

import avro.schema
from avro.datafile import DataFileWriter
from avro.io import DatumWriter

from kafka import *

def parse_args():
    parser = argparse.ArgumentParser(description='pcap2avro - Serialize IP packets from pcap files into Avro format')
    parser.add_argument('pcap_files', metavar='file', nargs='+',
                        help='pcap files to     serialize into Avro')
    parser.add_argument('-o', '--out', metavar='output file', nargs='?',
                        help='Write output to this file')
    parser.add_argument('--mode', choices=('file', 'kafka'), nargs='?', default='file',
                        help='Output mode; ')
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
    return p==dpkt.ip.IP_PROTO_TCP or p==dpkt.ip.IP_PROTO_UDP

def proto_id_to_name(p):
    if p==dpkt.ip.IP_PROTO_ICMP:
        return 'ICMP'
    elif p==dpkt.ip.IP_PROTO_TCP:
        return 'TCP'
    elif p == dpkt.ip.IP_PROTO_UDP:
        return 'UDP'
    else:
        return 'other'


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


def icmp_type_name(type):
    if type is dpkt.icmp.ICMP_CODE_NONE:
        return 'ICMP without codes'
    elif type is dpkt.icmp.ICMP_ECHOREPLY:
        return 'echo reply'
    elif type is dpkt.icmp.ICMP_UNREACH:
        return 'ICMP dest unreachable'
    elif type is dpkt.icmp.ICMP_SRCQUENCH:
        return 'ICMP source quench'
    elif type is dpkt.icmp.ICMP_REDIRECT:
        return 'ICMP Redirect'
    elif type is dpkt.icmp.ICMP_ALTHOSTADDR:
        return 'ICMP alternate host address'
    elif type is dpkt.icmp.ICMP_ECHO:
        return 'ICMP echo'
    elif type is dpkt.icmp.ICMP_RTRADVERT:
        return 'ICMP Route advertisement'
    elif type is dpkt.icmp.ICMP_RTRSOLICIT:
        return 'ICMP Router solicitation'
    elif type is dpkt.icmp.ICMP_TIMEXCEED:
        return 'ICMP time exceeded, code:'
    elif type is dpkt.icmp.ICMP_PARAMPROB:
        return 'ICMP ip header bad'
    elif type is dpkt.icmp.ICMP_TSTAMP:
        return 'ICMP timestamp request'
    elif type is dpkt.icmp.ICMP_TSTAMPREPLY:
        return 'ICMP timestamp reply'
    elif type is dpkt.icmp.ICMP_INFO:
        return 'ICMP information request'
    elif type is dpkt.icmp.ICMP_INFOREPLY:
        return 'ICMP information reply'
    elif type is dpkt.icmp.ICMP_MASK:
        return 'ICMP address mask request'
    elif type is dpkt.icmp.ICMP_MASKREPLY:
        return 'ICMP address mask reply'
    elif type is dpkt.icmp.ICMP_TRACEROUTE:
        return 'ICMP traceroute'
    elif type is dpkt.icmp.ICMP_DATACONVERR:
        return 'ICMP data conversion error'
    elif type is dpkt.icmp.ICMP_MOBILE_REDIRECT:
        return 'ICMP mobile host redirect'
    elif type is dpkt.icmp.ICMP_IP6_WHEREAREYOU:
        return 'ICMP IPv6 where-are-you'
    elif type is dpkt.icmp.ICMP_IP6_IAMHERE:
        return 'ICMP IPv6 i-am-here'
    elif type is dpkt.icmp.ICMP_MOBILE_REG:
        return 'ICMP mobile registration req'
    elif type is dpkt.icmp.ICMP_MOBILE_REGREPLY:
        return 'ICMP mobile registration reply'
    elif type is dpkt.icmp.ICMP_DNS:
        return 'ICMP domain name request'
    elif type is dpkt.icmp.ICMP_DNSREPLY:
        return 'ICMP domain name reply'
    elif type is dpkt.icmp.ICMP_PHOTURIS:
        return 'ICMP Photuris'
    elif type is dpkt.icmp.type_MAX:
        return 'ICMP Type Max'
    else:
        return 'ICMP Type Unknown'


def ingest_file(pcap_file):
    avro_schema_file = "./schema/ip.avsc"
    avro_output_file = pcap_file + '.avro'
    kafka_endpoint = "kafka01.steepbeach.net:9092"
    kafka_topic = "test01"

    # Initialize
    schema = read_avro_schema(avro_schema_file)
    pcap = read_pcap(pcap_file)
    packet_count = Counter(['total','IP','IPv6','dropped','TCP','UDP','ICMP','error'])

    #producer = init_kafka(kafka_endpoint)
    if args.mode == 'file':
        #TODO use with to open file
        try:
            file_writer = DataFileWriter(open(avro_output_file, "w"), DatumWriter(), schema)
        except Exception as e:
            print "Failed to open Avro output file %s" % avro_output_file
            print e
            sys.exit()
    elif args.mode == 'kafka':
        try:
            kafka = KafkaClient(kafka_endpoint)
            producer = SimpleProducer(kafka)
        except Exception as e:
            print "Failed to open Kafka connection at %s" % kafka_endpoint
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
        if ip.p not in [dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_UDP, dpkt.ip.IP_PROTO_TCP]:
            if (ip.p == dpkt.ip.IP_PROTO_IP6):
                packet_count['IPv6'] += 1
            packet_count['dropped'] += 1
            continue
        packet_count['IP'] += 1

        # Init protocol data
        tcp_data = None
        icmp_data = None
        udp_data = None

        if args.debug:
            # Do some conversions now
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            proto = proto_id_to_name(ip.p)
            packetlength = ip.len-ip.hl*4
            humanTS = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

        if ip.p == dpkt.ip.IP_PROTO_ICMP:
            packet_count['ICMP'] += 1
            icmp = ip.data

            icmp_data = {}
            icmp_data['type'] = icmp.type
            icmp_data['typeName'] = icmp_type_name(icmp.type)
            icmp_data['code'] = icmp.code

            if(args.debug):
                pktStr =  "%d | %s | %s | %s -> %s %s %d/%d" \
                      % (packet_count['total'], humanTS, proto, src, dst, \
                         icmp_data['typeName'], icmp_data['type'], icmp_data['code'])
                print pktStr

        elif ip.p == dpkt.ip.IP_PROTO_TCP:
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

        elif (ip.p == dpkt.ip.IP_PROTO_UDP):
            packet_count['UDP'] += 1
            udp = ip.data

            if args.debug:
                pktStr =  "%d | %s | %s | %s : %d -> %s : %d, len: %d" \
                      % (packet_count['total'], humanTS, proto, src, udp.sport, dst, udp.dport, udp.ulen)
                print pktStr

            udp_data = {}
            udp_data['src_port'] = udp.sport
            udp_data['dst_port'] = udp.dport
            udp_data['length']   = udp.ulen

        packet = {
            "ts": ts,

            "ttl": ip.ttl,
            "proto_id": ip.p,
            "src_addr": socket.inet_ntoa(ip.src),
            "dst_addr": socket.inet_ntoa(ip.dst),
            "length": ip.len,

            "tcp":  tcp_data,
            "udp":  udp_data,
            "icmp": icmp_data
        }

        if args.mode == 'file':
            file_writer.append(packet)
        elif args.mode == 'kafka':
            # writer =  cStringIO.StringIO()
            # encoder = avro.io.BinaryEncoder(writer)
            # datum_writer = avro.io.DatumWriter(schema)
            #
            # #producer = SimpleProducer(kafka_conn)
            # for topic in ["DUMMY_LOG"]:
            #     writer.truncate(0)
            #     datum_writer.write(packet, encoder)
            #     bytes = writer.getvalue()
            #     print "---"
            #     print bytes
            #     #producer.send_messages(topic, bytes)

            writer = avro.io.DatumWriter(schema)
            bytes_writer = io.BytesIO()
            encoder = avro.io.BinaryEncoder(bytes_writer)
            writer.write(packet, encoder)
            bytes = bytes_writer.getvalue()
            try:
                producer.send_messages(kafka_topic, bytes)
            except Exception as e:
                print e

            if args.debug:
                print "Sent."
            writer.close()

    if args.mode == 'file':
        file_writer.close()


if __name__ == '__main__':
    main()