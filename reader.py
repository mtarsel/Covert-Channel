import thread
import threading
import socket
import time
from scapy.all import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])
pkt = None
lock = threading.Lock()

def parse():
	global pkt
	try:
		cs = pkt[TCP].chksum#TCP checksum is where message should be
	except IndexError as E:
		return
	if pkt[TCP].flags == 0x080:#our packet has TCP.flags = "C"
		print "Aha! A message! " + str(cs)#print TCP checksum
		exit()
	return

def sniffer():
	global pkt
	while True:
		p = sniff(count=1, store=1)
		lock.acquire()
		pkt = p[0]
		parse()
		lock.release()

def server():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print 'Socket created'

	s.bind((host, port))

	s.listen(10)
	conn, addr = s.accept()

	data = conn.recv(1)
	while data != "":
		print data
		data = conn.recv(1)

thread.start_new_thread(sniffer, ())
server()
