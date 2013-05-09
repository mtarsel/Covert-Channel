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

Message is currently hardcoded.  Fails to parse message, use wireshark and
examine TCP checksum to find message "Hi".
