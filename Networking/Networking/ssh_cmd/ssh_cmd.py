import threading
import paramiko
import subprocess

#This function opens an SSH session using IP, username, and password provided in args,
#and runs a single commmand that is also passed in args
def ssh_command(ip, user, passwd, command):
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
        ssh_session.exec_command(command)
        print ssh_session.recv(1024)
    return
