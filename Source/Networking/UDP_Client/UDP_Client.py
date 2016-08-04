#this is an example of a simple udp client
#import socket lib
import socket

#define targets
target_host = "127.0.0.1"
target_port = 80

#create Socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#send some data (Since this is UDP we do not connect first)
client.sendto("AABBCCDD",(target_host,target_port))

#receive some data
data, addr = client.recvfrom(4096)

print data