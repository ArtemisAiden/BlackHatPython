import sys
import socket
import threading

#This function sets up our local listener 
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

#This function handles the proxying of data between local and remote hosts
def proxy_handler(client_socket, remote_host,remote_port,receive_first):
	#first create raw socket for remote connection
	remote_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	#connect to the remote host
	remote_socket.connect((remote_host,remote_port))

	#receive data from remote host if specified
	if receive_first == True:
		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)
		#send data to response handler
		remote_buffer = response_handler(remote_buffer)
		#check to see if there is data to send to our local client and if so send it
		if len(remote_buffer):
			print "[<==] Sending %d bytes to local host." % len(remote_buffer)
			client_socket.send(remote_buffer)
	#define loop to read from local
		#send to remote, send to local
	#lather rinse repeat
	while True:
		#read from local host
		local_buffer = receive_from(client_socket)
		if len(local_buffer):
			print "[==>] Received %d bytes from local host." % len(local_buffer)
			hexdump(local_buffer)
			#send local buffer to request handler
			local_buffer = request_handler(local_buffer)
			#send data to remote host
			remote_socket.send(local_buffer)
			print "[==>] Sent to remote host"
			#receive response back from remote host
			remote_buffer = receive_from(remote_socket)
			if len(remote_buffer):
				print "[<==] Received %d bytes from remote host." % len(remote_buffer)
				hexdump(remote_buffer)
				#send response to response handler
				remote_buffer = response_handler(remote_buffer)
				#send response to local socket
				client_socket.send(remote_buffer)
				print "[<==] Sent to local host."
			if not len(local_buffer) or len(remote_buffer):
				client_socket.close()
				remote_socket.close()
				print "No more data. Closing connections."

				break

#This function takes bytes and converts to hex
def hexdump(src, length=16):
	#create empty list to store result in
	result = []
	#nifty way to define variable based on result of if statements
	#set digits to 4 if src is unicode and 2 otherwise
	digits  = 4 if isinstance(src, unicode) else 2
	for i in xrange(0, len(src), length):
		s = src[i:i+length]
		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b' '.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
		result.append(b"%0C %-*s" % (i,length*(digits+1), hexa, text))
	print b'\n'.join(result)

#This function reads data from remote host and returns the buffer of data
def receive_from(connection):
	#initialize buffer to contain string
	buffer = ""
	#Set a 2 second timeout (may need to be adjusted based on connection to target)
	connection.settimeout(2)
	try:
		#keep reading into buffer until there is no more data or we timeout
		while True:
			data = connection.recv(4096)
			if not data:
				break
			buffer += data
	except:
		pass
	return buffer

#This function modifies any request destined for the remote host
def request_handler(buffer):
	#TODO: perform packet modifcations
	return buffer

#This function modifies any responses destined for the local host
def response_handler(buffer):
	#TODO: perform packet modifications
	return buffer

#This function represent the main execution flow of the program
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
