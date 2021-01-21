from scapy.all import *
import sys

def parsePCAP(pkts):
  for pkt in pkts:
    print("Source IP: " + pkt[IP].src)
    print("Destination IP: " + pkt[IP].dst)
    print("Source port: " + str(pkt[TCP].sport))
    print("Destinations port: " + str(pkt[TCP].dport))
    print("Packet Payload: " + str(pkt[TCP].payload))	

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("usage: python lab3.py [pcap]")
    sys.exit()	 
  pcap = rdpcap(sys.argv[1])
  pcap = [pkt for pkt in pcap if TCP in pkt]
  parsePCAP(pcap)