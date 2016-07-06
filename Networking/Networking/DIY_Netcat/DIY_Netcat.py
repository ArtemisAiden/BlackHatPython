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

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l","--listen"):
            listen = True
        elif o in ("-e","--execute"):
            execute = a
        elif o in ("-c","--commandshell"):
            command = True
        elif o in ("-u","--upload"):
            upload_destination = a
        elif o in ("-t","--target"):
            target = a
        elif o in ("-p","--port"):
            port = int(a)
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

def client_sender(buffer):
    pass
def server_loop():
    pass
def run_command(command):
    pass
def client_handler(client_socket):
    pass

#execute main
main()