import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
	#create raw IPv4 socket
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		#bind socket to local host and port
		server.bind((local_host,local_port))
	except:
		#Throw Exception and Exit if socket failed to bind
		print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
		print "[!!] Check for other listening sockets on port or permissions"
		sys.exit(0)

	print "[*] Listening on %s:%d" % (local_host,local_port)
	#listen for up to 5 connections
	server.listen(5)

	while True:
		client_socket = server.accept()
		#print local connection information
		print "[==>] Received incoming connection from %s:%d" % (addr[0],addr[1])
		#start a thread for the connection
		proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,remote_host,remote_port,receive_first))
		proxy_thread.start
def main():
	#verify that all 5 necessary arguments were provided and if not print usage and exit
	if len(sys.argv[1:]) != 5:
		print "Usage: ./TCP_Proxy.py [local host] [local port] [remote host] [remote port] [receive first]"
		print "Example: ./TCP_Proxy.py 127.0.0.1 9000 10.10.10.2 9000 True"
		sys.exit(0)
	#setup local listening params
	local_host = sys.argv[1]
	local_port = int(sys.argv[2])

	#setup remote target params
	remote_host = sys.argv[3]
	remote_port = int(sys.argv[4])

	#receive_first determines whether we should connect and receive data before sending to the remote host
	if sys.argv[5] == "True" or "true" or "TRUE":
		receive_first = True
		print "Receive First flag was set to True."
		print "We will connect to remote host and receive data prior to sending"
	else:
		receive_first = False
		print "Receive First flag was not set to True"
		print "We will send data first to remote host."

	#spin up listening socket
	server_loop(local_host,local_port,remote_host,remote_port,receive_first)

main()
