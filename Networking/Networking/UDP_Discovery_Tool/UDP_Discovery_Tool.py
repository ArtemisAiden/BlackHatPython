import socket
import os
import sys

if sys.argv:
    host = str(sys.argv[1])
    print "Will listen on %s" % host
else:
    #host to listen on
    host = "127.0.0.1"
    print "Will listen on 127.0.0.1"
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

#read a single packet
print sniffer.recvfrom(65565)

#If windows turn off promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)