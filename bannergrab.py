import socket,sys
ip = '192.168.43.200'
port = int(8888)

try:
    sys.stdout.flush()
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(20)
    connect = s.connect((ip,port))
    s.send('GET HTTP/1.1 \r\n')
    banner = s.recv(1024)
    print banner
except:
    pass
import os
os.dup()
