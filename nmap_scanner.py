#!/usr/bin/env python

import sys
import os
import time
try:
    import nmap
except:
    sys.exit('[!] Please install python-nmap : sudo pip install nmap')
try:
    import netifaces
except:
    sys.exit('[!] Please Install netifaces module: pip install netifaces')

class Verify:
    def __init__(self):
        self.network = {}
        self.gateway = {}
        self.interfaes = []
        self.gw_dict ={}
        self.host_detail = {}
        self.host = {}


    def get_allinterfaces(self):
        self.interfaces = netifaces.interfaces()
        return self.interfaces

    def get_gateway(self):
        gws = netifaces.gateways()
        try :
            for gw in gws:
                gw_iface = gws[gw][netifaces.AF_INET]
                gw_ipv4,iface = gw_iface[0],gw_iface[1]
                gw_list = [iface,gw_ipv4]
                self.gw_dict[gw] = gw_list
                return self.gw_dict
        except:
            pass

    def get_hostdetil(self, interface):
        addr = netifaces.ifaddresses(interface)
        ipv4_head = addr[netifaces.AF_INET]
        mac_head  = addr[netifaces.AF_LINK]
        host_ipv4, host_mac = ipv4_head[0].get('addr'), mac_head[0].get('addr')
        self.host_detail = {'ipv4' : host_ipv4,'mac' : host_mac }
        return self.host_detail

    def get_host(self,gateway):
        for key, value in gateway.iteritems():
            iface, ipv4 = value[0] , value[1]
            self.host = self.get_hostdetil(iface)
            return {'localhost' : self.host, 'gateway' : ipv4}






class Run():
    def run_nm(self,sn_type,host,port):
        if sn_type == 'noise':
            self.run(host,port,arg='-sT -sV -O')
        elif sn_type == 'medium':
            self.run(host,port,arg='-sA -sV')
        elif sn_type == 'quiet':
            self.run(host,port,arg='-sS -sV')

    def run(self,host,port,arg):

        try :
            nm = nmap.PortScanner()
        except:
            sys.exit('[!] Please Install Nmap')

        print('[+] Scanning Host ..... ')
        print('[+] Scanning Port: %s') % (port)
        nm.scan(hosts=host,ports=port,arguments=arg,sudo=True)
        tar_host = nm.all_hosts().pop()
        stats = nm.scanstats()
        scan_info = nm.scaninfo()
        info = nm[tar_host]

        try :
            host_name = info['hostnames']
            address   = info['addresses']
            tcp       = info['tcp']
            status    = info['status']
        except:
            pass

        try :
            print('[+] Loading Host detail ..')
            print('[+] Host Name : %s') %(host_name[0]['name'])
            print('[+] Host Ipv4 address: %s') %(address['ipv4'])
            print('[+] Host Status: %s') %(status['state'])
        except:
            pass

        if 'osmatch' in info:
            for osmatch in info['osmatch']:
                print('[+] OsMatch.Name : {0}'.format(osmatch['name']))
                print('[+] OsMatch.Accuracy : {0}'.format(osmatch['accuracy']))
                print('[+] OsMatch.Line : {0}'.format(osmatch['line']))

                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print('[+] OsClass.type : {0}'.format(osclass['type']))
                        print('[+] OsClass.vendor : {0}'.format(osclass['vendor']))
                        print('[+] OsClass.osfamily : {0}'.format(osclass['osfamily']))
                        print('[+] OsClass.osgen : {0}'.format(osclass['osgen']))
                        print('[+] OsClass.accuracy : {0}'.format(osclass['accuracy']))
                        print('')
                        break
                break
        if 'fingerprint' in scan_info:
            print('[+] Fingerprint : {0}'.format(scan_info['fingerprint']))

        try:
            for pt in tcp:
                port_no = pt
                data = tcp[port_no]
                s_banner = data['product']
                s_state = data['state']
                s_version = data['version']
                s_info = data['extrainfo']
                s_cpe = data['cpe']
                s_name = data['name']
                if s_state == 'closed':
                    print('port\tstate')
                    print('%s\t%s') % (port_no,s_state)
                else:
                    if port_no != '' and s_state != '':
                        print('port\tstate')
                        print('%s\t%s') % (port_no,s_state)
                    if s_banner != '':
                        print('[+] Running Service: %s') % (s_banner)
                    if s_name != '':
                        print('[+] Running Protocol: %s') % (s_name)
                    if s_version != '':
                        print('[+] Service Version: %s') % (s_version)
                    if s_cpe != '':
                        print('[+] cpe detail : %s') % (s_cpe)
        except:
            pass


class Scan(Run):
    def __init__(self):
        self.result = {}



    def quite(self,host,port='1-1000'):
        self.run_nm('quiet',host,port)

    def noise(self,host,port='1-1000'):
        self.run_nm('noise',host,port)

    def medium(self,host,port='1-1000'):
        self.run_nm('medium',host,port)

    def common(self):
        port_tcp_udp = '1433,1434,3306,5433,2409,111,445,21,3389,22,23,6000,6001,6002,6003,6004,6005,5900,9999,25,79,80,443,8080,8443,8888,8834'
        return port_tcp_udp


def __init__():
    if len(sys.argv) == 1 or sys.argv[1] == '-h':
        print '''
        Nmap Auto Scanner By Magic
                version 1
         '''
        print('-h \t for help')
        print('-quite for quitest scan type, without OS fingerprinting')
        print('-medium for medium scan type')
        print('-nosie for nosiest scan type with OS fingerprinting but faster')
        print('-common for most common port scan')
        print('--host for the host you want to scan')
        print('-p to scan specify ports')
        print('Eg:python nmap_scanner.py -quite --host 192.168.43.170 -common')
        print('Eg:python nmap_scanner.py -noise --host 192.168.43.170 -p 22,23,80,5900')
        print('Eg:python nmap_scanner.py -quite --host 192.168.43.170')

        sys.exit(0)
    else :
        if not '--host' in sys.argv:
            print('[!] Please Enter Host ip address !!')
        else :
            if '--host' in sys.argv:
                ipv4_index = sys.argv.index('--host')+1
                global ipv4
                ipv4 = sys.argv[ipv4_index]
            if '-quite' in sys.argv and '-common' in sys.argv:
                port = s.common()
                s.quite(ipv4,port)
                sys.exit(0)
            if '-medium' in sys.argv and '-common' in sys.argv:
                port = s.common()
                s.medium(ipv4,port)
                sys.exit(0)
            if '-noise' in sys.argv and '-common' in sys.argv:
                port = s.common()
                s.noise(ipv4,port)
                sys.exit(0)
            if not '-p' in sys.argv:
                if '-noise' in sys.argv :
                    s.noise(ipv4)
                    sys.exit(0)
                if '-quite' in sys.argv:
                    s.quite(ipv4)
                    sys.exit(0)
                if '-medium' in sys.argv:
                    s.medium(ipv4)
                    sys.exit(0)
            else:
                port_index = sys.argv.index('-p')+1
                port = sys.argv[port_index]
                if '-noise' in sys.argv :
                    s.noise(ipv4,port)
                    sys.exit(0)
                if '-quite' in sys.argv:
                    s.quite(ipv4,port)
                    sys.exit(0)
                if '-medium' in sys.argv:
                    s.medium(ipv4,port)
                    sys.exit(0)


s = Scan()

__init__()
