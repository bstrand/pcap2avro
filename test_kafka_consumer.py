__author__ = 'bstrand'

import sys
import socket
import argparse
import io
from datetime import datetime
from collections import Counter

import kafka
import avro.schema
from avro.datafile import DataFileWriter
from avro.io import DatumWriter


kafka_endpoint = "ip-172-31-23-112:9092"
topics = ["test02"]
consumer_group = "test_kafka_consumer"
kafka_client = kafka.KafkaClient(kafka_endpoint)

topic = topics[0]
consumer = kafka.SimpleConsumer(kafka_client, consumer_group, topic)

# reeeeeewiiiiiiind
#consumer.seek(0, 0)

def dump_message(message):
    print "****"
    print (message)
    print "Message length: %s" % (len(message))
    print "* Offset *"
    print  message[0]
    # get the value back out of the kafka consumer's fetched message
    print "* Message *"
    print message[1].value
    print len(message[1].value)
    print "\n"

def deser_message(message):
    schema = avro.schema.parse(open('./schema/ip.avsc').read())
    reader = io.BytesIO(message[1].value)
    decoder = avro.io.BinaryDecoder(reader)
    datum_reader = avro.io.DatumReader(schema)

    pkt = datum_reader.read(decoder)
    print pkt["proto_id"]
    print pkt["src_addr"]
    print pkt["dst_addr"]
    reader.close()

try:
    messages = consumer.get_messages(count=100, block=False)
    # it looks like we get a TypeError Exception if no new messages exist
    for message in messages:
        #dump_message(message)
        deser_message(message)
    print "\n"
    print "Received %s total messages" % (len(messages))

except KeyboardInterrupt:
    pass

except TypeError as e:
    print "Got TypeError"
    print e

except Exception as e:
    print "Some other exception!"
    print e

consumer.commit()

kafka_client.close()
