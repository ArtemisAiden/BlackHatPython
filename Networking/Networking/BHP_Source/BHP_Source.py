import socket
import sys
import getopt
import threading
import subprocess

def usage():
    print "Usage: netcat_awesome.py -t <HOST> -p <PORT>"
    print "  -l --listen                  listen on HOST:PORT"
    print "  -e --execute=file            execute the given file"
    print "  -c --command                 initialize a command shell"
    print "  -u --upload=destination      upload file and write to destination"
    print
    print "Examples:"
    print "netcat_awesome.py -t localhost -p 5000 -l -c"
    print "netcat_awesome.py -t localhost -p 5000 -l -u=example.exe"
    print "netcat_awesome.py -t localhost -p 5000 -l -e='ls'"
    print "echo 'AAAAAA' | ./netcat_awesome.py -t localhost -p 5000"
    sys.exit(0)

LISTEN   = False
COMMAND  = False
UPLOAD   = False
EXECUTE  = ''
TARGET   = ''
UP_DEST  = ''
PORT     = 0

def main():
    global LISTEN
    global PORT
    global EXECUTE
    global COMMAND
    global UP_DEST
    global TARGET

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu", \
            ["help", "LISTEN", "EXECUTE", "TARGET", "PORT", "COMMAND", "UPLOAD"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listen'):
            LISTEN = True
        elif o in ('-e', '--execute'):
            EXECUTE = a
        elif o in ('-c', '--commandshell'):
            COMMAND = True
        elif o in ('-u', '--upload'):
            UP_DEST = a
        elif o in ('-t', '--target'):
            TARGET = a
        elif o in ('-p', '--port'):
            PORT = int(a)
        else:
            assert False, "Unhandled option"

    # NETCAT client
    if not LISTEN and len(TARGET) and PORT > 0:
        buffer = sys.stdin.read()
        client_sender(buffer)

    # NETCAT server
    if LISTEN:
        if not len(TARGET):
            TARGET = '0.0.0.0'
        server_loop()

def client_sender(buffer):
    client = socket.socket( socket.AF_INET, socket.SOCK_STREAM )

    try:
        client.connect(( TARGET, PORT ))

        # test to see if received any data
        if len(buffer):
            client.send(buffer)

        while True:
            # wait for data
            recv_len = 1
            response = ''

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data
                if recv_len < 4096:
                    break
            print response

            # wait for more input until there is no more data
            buffer = raw_input('')
            buffer += '\n'

            client.send(buffer)

    except:
        print '[*] Exception. Exiting.'
        client.close()

def server_loop():
    server = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    server.bind(( TARGET, PORT ))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        client_thread = threading.Thread( target =client_handler, \
                args=(client_socket,))
        client_thread.start()

def client_handler(client_socket):
    global UPLOAD
    global EXECUTE
    global COMMAND

    # check for upload
    if len(UP_DEST):
        file_buf = ''

        # keep reading data until no more data is available
        while 1:
            data = client_socket.recv(1024)
            if data:
                file_buffer += data
            else:
                break

        # try to write the bytes (wb for binary mode)
        try:
            with open(UP_DEST, 'wb') as f:
                f.write(file_buffer)
                client_socket.send('File saved to %s\r\n' % UP_DEST)
        except:
            client_socket.send('Failed to save file to %s\r\n' % UP_DEST)

    # Check for command execution:
    if len(EXECUTE):
        output = run_command(EXECUTE)
        client_socket.send(output)

    # Go into a loop if a command shell was requested
    if COMMAND:
        while True:
            # show a prompt:
            client_socket.send('NETCAT: ')
            cmd_buffer = ''

            # scans for a newline character to determine when to process a command
            while '\n' not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # send back the command output
            response = run_command(cmd_buffer)
            client_socket.send(response)

def run_command(command):
    command = command.rstrip()
    print command
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, \
                shell=True)
    except:
       output = "Failed to execute command.\r\n"
    return output

if __name__ == '__main__':
    main()