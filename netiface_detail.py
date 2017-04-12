import sys
import os
#import sys module for exits function

#here we need to catach exception because netifaces modules do not include in default
try :
    import netifaces
except:
    #sys.exit('[!] You need to install netifaces module: sudo pip install netifaces')
    os.system('pip install netifaces')

#function to get interface name
def get_interface():
    interface = netifaces.interfaces()
    #get all interface of machine
    return interface

def get_gateway():
    gw_dict={}
    #create dictionary to keep gateway name, ip address and interface
    gws = netifaces.gateways()
    #get gateway interfaces
    try:
        for gw in gws:
            gw_iface = gws[gw][netifaces.AF_INET]
            #get ipv4 default gateway interface
            iface,gw_addr = gw_iface[1],gw_iface[0]
            #seprate interface name and ip address
            gw_list = [iface,gw_addr]
            #add interface name and ip to list
            gw_dict[gw] = gw_list
            #add list to dictionary
    except:
        pass
    return gw_dict
    #return gateway dictionary


def get_address(interface):
    addr = netifaces.ifaddresses(interface)
    #extract all addresses for each interface
    link_addr = addr[netifaces.AF_LINK]
    #extract all MAC address information From the addr
    iface_addr = addr[netifaces.AF_INET]
    #extract all ipv4 address information from addr
    link_dict = link_addr[0]
    #extract dictionary value from the list
    iface_dict = iface_addr[0]
    #extract dictionary value from the list
    harwr_addr = link_dict.get('addr') # another format link_dict['addr']
    #get MAC address
    broad_addr = iface_dict.get('broadcast')
    #get Broadcast address
    net_addr   = iface_dict.get('netmask')
    #get subnetmask address
    host_addr  = iface_dict.get('addr')
    #get ipv4 address of interface
    return harwr_addr,broad_addr,net_addr,host_addr

def get_networks(gateways):
    network = {}
    for key, value in gateways.iteritems():
        iface,gw_addr = value[0],value[1]
        #get value from the dictionary
        harwr_addr,broad_addr,net_addr,host_addr = get_address(iface)
        #get value from get_address() function
        network = {'hawr_addr': harwr_addr,'broad_addr':broad_addr,'net_addr':net_addr,'host_addr':host_addr,'gw_addr':gw_addr}
        #create dicitionary to return all value

    return network
    #return the all data

gateway = {}
gateway = get_gateway()
network_interfaces={}
network_interfaces = get_networks(gateway)

def show_res(network):
    print('[+] IP address of host: %s') %(network['host_addr'])
    print('[+] Subnet Mask of the host: %s') %(network['net_addr'])
    print('[+] MAC address of host: %s') %(network['hawr_addr'])
    print('[+] Gateway of host: %s') %(network['gw_addr'])
    print('[+] Broadcast address of host: %s\n') %(network['broad_addr'])

show_res(network_interfaces)
