import thread
import threading
import socket
import time
from scapy.all import *
import sys

dst = sys.argv[1]
port = int(sys.argv[2])
pkt = None
lock = threading.Lock()

def craft(message):
	global pkt
	lock.acquire()
	pkt[TCP].seq += 1
	pkt[TCP].load = message
	pkt[TCP].ack = 0
	del pkt[IP].chksum
	del pkt[IP].len
	del pkt[TCP].chksum
	pkt[TCP].chksum = 72*256 + 105#hex= 0x4869, or “Hi”
	pkt[TCP].flags = "C" #this is how we identify our packet
	pkt.show2()
	lock.release()
	return pkt

def sniffer():
	global pkt
	while True:#change src address if not testing locally
		p = sniff(filter="tcp and type=0x800 and src=127.0.0.1 and dst=" + dst, count=1, store=1)
		try:
			p[0][TCP].seq
		except:
			continue
		lock.acquire()
		pkt = p[0]
		lock.release()

def client():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print 'Socket created'

	s.connect((dst, port))
	
	#send 5 packets. Fifth packet is crafted packet

	for i in range(5):
		s.send(str(i))
		time.sleep(.1)
	send(craft('5'))#our crafted packet
	time.sleep(.1)
	for i in range(5, 10):#send 5 more packets
		s.send(str(i))
		time.sleep(.1)

thread.start_new_thread(sniffer, ())
client()
