#import libs
import socket

#define targets
target_host = "www.google.com"
target_port = 80

#create Socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#connect to target
client.connect((target_host,target_port))

#send some data
client.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

#receive some data
response = client.recv(4096)

print response