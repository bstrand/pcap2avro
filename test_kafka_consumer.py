__author__ = 'bstrand'

# import sys
# import socket
# import argparse
# import io
# from datetime import datetime
# from collections import Counter

import kafka
import avro.schema
from avro.datafile import DataFileWriter
from avro.io import DatumWriter


kafka_endpoint = "ip-172-31-23-112:9092"
topics = ["test01"]
consumer_group = "test_kafka_consumer"
kafka_client = kafka.KafkaClient(kafka_endpoint)

topic = topics[0]
consumer = kafka.SimpleConsumer(kafka_client, consumer_group, topic)

# reeeeeewiiiiiiind
#consumer.seek(0, 0)

try:
	messages = consumer.get_messages(count=2000, block=False)

	# it looks like we get a TypeError Exception if no new messages exist
	for message in messages:
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