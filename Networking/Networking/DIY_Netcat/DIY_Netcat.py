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
    print "Usage: DIY_Netcat.py -t target_host - p port"
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
        opts, args = getopt(sys.argv[1:], "hle:t:p:cu:", 
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
    if (not listen) and (len(target)) and (port > 0):
        #read in the buffer from commandline
        #this will block so send CTRL-D if not sending input
        buffer = sys.stdin.read()
        #send data after read
        client_sender(buffer)
    #if we are listening call server_loop() to set up listener
    if listen:
        server_loop()
#define a tcp client to allow communication from stdin to target
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
                data    = client.recv(4096)
                recv_len = len(data)
                #add data to response
                response += data

                #break loop once a full packet of data has not been received.  Presumably EOF
                if recv_len < 4096:
                    break

                #print full response received from socket stream
                print response,

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

def server_loop():
    pass
def run_command(command):
    pass
def client_handler(client_socket):
    pass

#execute main
main()