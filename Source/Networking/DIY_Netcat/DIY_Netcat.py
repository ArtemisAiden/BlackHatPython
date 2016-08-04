#import required libs
import sys
import socket
import getopt
import threading
import subprocess

#define global variables
listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

#define usage text
def usage():
    print "DIY_Netcat"
    print 
    print "Usage: DIY_Netcat.py -t target_host -p port"
    print "-l --listen                  - listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run     - execute given file upon receiving connection"
    print "-c --command                 - initialize a command shell"
    print "-u --upload=destination      - upon receiving connectionupload a file and write it to destination"
    print
    print
    print "Examples:"
    print "DIY_Netcat - t 192.168.1.50 -p 5555 -l -c"
    print "DIY_Netcat - t 192.168.1.50 -p 5555 -l -u=c:\\target.exe"
    print "DIY_Netcat - t 192.168.1.50 -p 5555 -l -e=\"cat /etc/password\""
    print "echo 'ABCDEFGHI' | ./DIY_Netcat.py -t 192.168.1.50 -u 135"
    sys.exit(0)

#define main function to be executed when the script is run
def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target
    
    #verify args were passed and if not print usage
    if not len(sys.argv[1:]):
        usage()
    #read command line args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", 
                            ["help", "listen", "execute", "target" ,"port", "command", "upload"])
    #if error print it and then print usage
    except getopt.GetoptError as err:
        print str(err)
        usage()
    #loop through opts defining option as o and corresponding argument as a
    for o,a in opts:
        #if help is passed print usage
        if o in ("-h", "--help"):
            usage()
        #if listen is passed set listen to true
        elif o in ("-l","--listen"):
            listen = True
        #if execute is passed then set execute to the value of the argument passed with it
        elif o in ("-e","--execute"):
            execute = a
        #if commandshell is passed then set command to true 
        elif o in ("-c","--commandshell"):
            command = True
        #if upload is passed set upload to value of the argument passed with it
        elif o in ("-u","--upload"):
            upload_destination = a
        #if target is passed then set target to the value of argument passed with it
        elif o in ("-t","--target"):
            target = a
        #if port is passed then set port to value of argument passed with it cast to int
        elif o in ("-p","--port"):
            port = int(a)
        #if none of the above trigger write an a debug exception for the unhandled options
        else:
            assert False, "Unhandled Option"
    #check if we are listening or just sending data from stdin
    #if not listening read std in and save to buffer.  
    #Then call client_sender() to send data from buffer to client
    if not listen and len(target) and port > 0:
        #read in the buffer from commandline
        #this will block so send CTRL-D if not sending input
        buffer = sys.stdin.read()
        #send data after read
        client_sender(buffer)
    #if we are listening call server_loop() to set up listener
    if listen:
        server_loop()

#This function defines a tcp client to allow communication from stdin to target
def client_sender(buffer):
    #create ipv4 (af_Inet) streaming (Sock_Stream) socket
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        #connect socket to target on port
        client.connect((target,port))

        #Check if there is data in buffer
        if len(buffer):
            #send buffer
            client.send(buffer)
        #loop until break is called
        while True:
            #define variable to store the response and another another to dertermine when the message is finished
            recv_len = 1
            response = ""
            
            while recv_len:
                #save 4096 bytes of data received to data
                data = client.recv(4096)
                recv_len = len(data)
                #add data to response
                response += data

                #break loop once a full packet of data has not been received.  Presumably EOF
                if recv_len < 4096:
                    break

                #print full response received from socket stream
                print response

                #request further input for buffer
                buffer = raw_input("")
                #adding a new line to make this function compatible with the spawn shell function
                buffer += "\n"

                #send new buffer
                client.send(buffer)


    except:
        print "[*] Exception Encountered.  Closing Connection and Exiting."
        #tear down connection
        client.close()

#This function will setup a simple TCP listening server we can connect to
def server_loop():
	global port
	global target
    #if no target is defined, we listen on all interfaces
    #0.0.0.0 represents all interfaces
	if not len(target):
		target = "0.0.0.0"
    #define server socketfor IPV4 and streaming
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #bind socket to target IP and port
	server.bind((target,port))
    #set socket to listen and accept up to five connections
	server.listen(5)

	while True:
        #this variable stores the incoming connection and address
		client_socket, addr = server.accept()

        #add connction to new thread so we can continue to listen
        #build thread to call client_handler with args as client_socket
		client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        #Start Thread and return to listening
		client_thread.start()
def client_handler(client_socket):
	global upload
	global command
	global execute
	#check for upload
	if len(upload_destination):
		#check to see if there is an upload
		file_buffer = ""
		#read data until there is no more available
		while True:
			data = client_socket.recv(1024)
			#if there is no data found in data break the loop
			if not data:
				break
			else:
				file_buffer += data
		#write the bytes out to file (wb for write bianary)
		try:
			file_descriptor = open(upload_destination,"wb")
			file_descriptor.write(file_buffer)
			file_descriptor.close()

			#acknowledge the file has been written
			client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
		except:
			client_socket.send("Failed to upload file to %s\r\n" % upload_destination)

		#check for command switch
	if len(execute):
		#run the command pass
		output = run_command(execute)
		#report the outcome
		client_socket.send(output)

	#create loop to spawn a command shell if requested
	if command:
		while True:
			#show a command prompt
			client_socket.send("<RemoteHost>:#")
			#now receive data until we receive an <Enter> cmd
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)
			#run cmd and save output to response
			response = run_command(cmd_buffer)
			#send back the reponse
			client_socket.send(response)
#This function runs the command passed to it.  
#It is also used to spawn a shell  on the local OS and return output to target
def run_command(command):
    #trim off the new line
    command = command.rstrip()

    #run the command and return output
    try:
        #this line uses subprocess library to execute the command passed in on -c or from stdin, and saves to output
        output = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command. \r\n"
    
    #return output to client
    return output



#execute main
main()