import socket
import os
import sys
import struct
from ctypes import *

#Check to see if listening target was defined and set host to listen on to that value
try:
    host = str(sys.argv[1])
    print "Target defined from command line.  Will listen on %s" % host
#If no target was defined from cmd line set host to listen to home
except:
    #host to listen on
    host = "127.0.0.1"
    print "No target to listen on was defined.  Will listen on 127.0.0.1"

class IP(Structure):
    _fields_ = [
        ("ihl",             c_ubyte, 4),
        ("version",         c_ubyte, 4),
        ("tos",             c_ubyte),
        ("len",             c_ushort),
        ("id",              c_ushort),
        ("offset",          c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum",             c_ushort),
        ("src",             c_ulong),
        ("dst",             c_ulong)
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        #map protocol constants to their protocols with dict
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        #human readable IPs
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        #human readable protocols
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

#set up raw socket and bind it to public interface
#if host is windows then use ip protocol
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
#if linux kernel use icmp
else:
    socket_protocol = socket.IPPROTO_ICMP

#Create RAW socket using parameters determined by OS
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
#Bind Socket to host name
sniffer.bind((host, 0))

#capture ip headers
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#if windows we need to set ioctl toset promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        #read in a single packet to buffer
        raw_buffer = sniffer.recvfrom(65565)[0]

        #build IP header from first 20 bytes of buffer
        ip_header = IP(raw_buffer[0:20])

        #print out protocol that was detected and hosts
        print "Protocol: %s SRC: %s \t->\t DST: %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
except KeyboardInterrupt:
    #If windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)