#import scapy 
from scapy.all import *

#Create packet callback function
def packet_callback(packet):
    print packet.show()

#fire up sniffer
sniff(prn=packet_callback,count=1)