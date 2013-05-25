Covert-Channel
==============

Created by Mick Tarsel and Sean Anderson

Covert Channel in TCP Checksum using Scapy

Requires Scapy v. 2.2
http://www.secdev.org/projects/scapy/

To run server:
sudo python reader.py [HOST IP] [PORT]

To run client:
sudo python client.py [HOST IP] [PORT]

Message is currently hardcoded. 

The sniffer does not acknowledge the crafted packet. This is presumably because the C standard socket library automatically drops packets with invalid checksums. On the other hand, Wireshark is quite capable of sniffing packets with invalid checksums :)
