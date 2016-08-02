import socket
import paramiko
import threading
import sys

#using the key from paramiko demo files. must be located in path with script
host_key = paramiko.RSAKey(filename='test_rsa.key')

class Server (paramiko.ServerInterface):
    def _init_(self):
        self.event = threading.Event
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        else:
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        if (username == 'test123') and (password == 'testing'):
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

server = sys.argv[1]
ssh_port = int(sys.argv[2])

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server,ssh_port))
    sock.listen(100)
    print "[+] Lisening for connection on port %d" % ssh_port
    client, addr = sock.accept()
except Exception, e:
    print '[-] Listen Failed: '+ str(e)
    sys.exit(1)
print '[+] Got a connection!'

try:
    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(host_key)
    server = Server()
    #Try and connect ssh session
    try:
        bhSession.start_server(server=server)
    except paramiko.ssh_exception, x:
        print "[-] SSH negotiation failed."
    #param for accept is the timeout
    chan = bhSession.accept(20)
    print "[+] Authenticated!"
    #print data received from SSH Client
    print chan.recv(1024)
    #send welcome banner to client
    chan.send('Welcome to bh_ssh!')
    #Create loop for SSH Session between client and server
    while True:
        try:
            command = raw_input("Enter a command: ").strip('\n')
            if command.lower() != 'exit':
                chan.send(command)
                print chan.recv(1024)+'\n'
            else:
                chan.send('exit')
                print "Exiting"
                bhSession.close()
                raise Exception ('exit')
        except KeyboardInterrupt:
            bhSession.close()
except Exception, e:
    print "[-] Caught Exception: " + str(e)
    try:
        bhSession.close()
    except:
        pass
    sys.exit(1)