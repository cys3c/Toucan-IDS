import logging
import socket, sys
from scapy.all import *
from scapy.error import Scapy_Exception
from scapy.all import sr1,IP,ICMP
from scapy.all import srp
from scapy.all import Ether, ARP, conf
import os
import sys
import threading
from threading import Thread
from optparse import OptionParser
import signal
from struct import *
import time
import pyshark

logging.basicConfig(filename='toucan.log',level=logging.DEBUG)


os.system("espeak 'Welcome to Toucan Network Defender'")


time_current = time.strftime("%I:%M:%S")
logging.info('%s' % time_current)
date_current = time.strftime("%d/%m/%Y\n")
logging.info('%s' % date_current)

print """
Toucan is a Wireless Intrusion Detection System written in python. Capabilities include scanning and defending hosts
on a network by actively monitoring traffic for both man in the middle and deauthentication attacks. This program is
not to be used on an unauthorized network and the creator is not responsible for any damage done. Using this program
means you understand and agree to these conditions.
"""

counter = 0
attacker_L2 = ''
attacker_MAC = ''
victim_MAC = ''
victim_L3 = ''

GATEWAY_IP = raw_input("Enter your Gateway IP: ")
logging.info('Gateway IP: %s' % GATEWAY_IP)

interface = raw_input("\nEnter your Network Interface: ")
logging.info('Interface: %s' % interface)

n_range = raw_input("\nEnter your network range to defend (in format 10.0.0.1/24): ")
logging.info('Network range to defend: %s' % n_range)

print"[*] Gateway Locked in..."
time.sleep(.2)
print"[*] Interface configured..."
time.sleep(.2)
print"[*] Network Range set..."
time.sleep(.2)
print"[*] Commensing..."
print"\n"

class perty_colors:

    Red ='\033[31m'
    Green ='\033[32m'
    Yellow ='\033[33m'
    Blue ='\033[34m'
    Pink ='\033[35m'
    Cyan ='\033[36m'
    White ='\033[37m'
    SBlack ='\033[0;30m'


def arp_network_range(iprange="%s" % n_range):

    logging.info('Sending ARPs to network range %s' % n_range)

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange), timeout=5)

    collection = []

    for snd, rcv in ans:

        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()

        logging.info('%s' % result)
        
        collection.append(result)

    for elem in collection:

        print elem

 
def arp_display(packet):

    if packet[ARP].op == 1: 

        logging.info('[*] Probe- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst))

        return '[*] Probe- %s is asking for L2 of %s' % (packet[ARP].psrc, packet[ARP].pdst)

    if packet[ARP].op == 2: 

        logging.info('[*] Response- %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc))

        return '[*] Response- %s L3 address is %s' % (packet[ARP].hwsrc, packet[ARP].psrc)
      

#   psuedo code---------------------------------------------
#   if hacker_is_found: (ARP policy violated)
#       attacker_L2 = '%s' % attacker_ARP_hwsrc
#-----------------------------------------------------------


def na_packet_discovery(neighbor_adv_packet):

  if neighbor_adv_packet.haslayer(IPv6) and neighbor_adv_packet.haslayer(ICMPv6ND_NA):

    print "Neighbor advertisement discovered: %s" % (neighbor_adv_packet.summary())

    print 'Neighbor solicitation source: %s, destination: %s ' % (neighbor_adv_packet[IPv6].src, neighbor_adv_packet[IPv6].dst)  

    logging.info('Neighbor advertisement source: %s, destination: %s' % (neighbor_adv_packet[IPv6].src, neighbor_adv_packet[IPv6].dst))


def ns_packet_discovery(neighbor_sol_packet):

  if neighbor_sol_packet.haslayer(IPv6) and neighbor_sol_packet.haslayer(ICMPv6ND_NS):

    print "Neighbor solicitation discovered: %s" % (neighbor_sol_packet.summary())

    print '[*]Neighbor solicitation source: %s, destination: %s' % (neighbor_sol_packet[IPv6].src, neighbor_sol_packet[IPv6].dst)  

    logging.info('Neighbor solicitation source: %s, destination: %s' % (neighbor_sol_packet[IPv6].src, neighbor_sol_packet[IPv6].dst))


def detect_deauth(deauth_packet):

  if deauth_packet.haslayer(Dot11) and deauth_packet.type == 0 and deauth_packet.subtype == 0xC:

    print "DEAUTH DETECTED: %s" % (deauth_packet.summary())

    logging.warning('Deauth detected. Responding...')



def get_mac_gateway(ip_address):

    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=2)

    for s, r in response:
        return r[Ether].src
    return None

    logging.info('Gateway Layer 2 address is: %s' % r[Ether].src)

    global GATEWAY_MAC 

    GATEWAY_MAC = "%s" % r[Ether].src


def defenseive_arps(GATEWAY_IP, GATEWAY_MAC):

    un_poison_victim = ARP()
    un_poison_victim.op = 2
    un_poison_victim.psrc = gateway_ip
    un_poison_victim.pdst = victim_L3
    un_poison_victim.hwdst = GATEWAY_MAC

    un_poison_gateway = ARP()
    un_poison_gateway.op = 2
    un_poison_gateway.psrc = victim_L3
    un_poison_gateway.pdst = gateway_ip
    un_poison_gateway.hwdst = victim_MAC

    send(un_poison_victim)
    send(un_poison_gateway)
    time.sleep(2)


def defensive_deauth(GATEWAY_MAC):

  conf.iface = interface
  bssid = GATEWAY_MAC 
#  global attacker_L2
  hacker = attacker_L2
  count = 77
  conf.verb = 0 

  packet = RadioTap()/Dot11(type=0,subtype=12,addr1=hacker,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7) 

  logging.info('Intruder at %s is being kicked off network' % hacker)

  for n in range(int(count)):

    sendp(packet)
    print 'Removing malicious host at:' + hacker + 'off of network.'


def monitor_traffic():

  monitor = pyshark.LiveCapture(interface='%s' % interface)

  monitor.sniff(timeout=50)

  for packet in monitor.sniff_continuously(packet_count=5):

    print 'Traffic detected: ', packet

def sniff_arps():

  sniff(filter = "arp", prn = arp_display)

def sniff_deauth():

  sniff(iface="%s" % interface, prn = detect_deauth)

def sniff_ns():

  sniff(iface="%s" % interface, prn = ns_packet_discovery) 

def sniff_na():

  sniff(iface="%s" % interface, prn = na_packet_discovery)


if __name__ == '__main__':

    GATEWAY_MAC = get_mac_gateway(GATEWAY_IP)

    print "[*] Gateway %s is at %s" % (GATEWAY_IP, GATEWAY_MAC)

    arp_network_range()

    Thread(target = sniff_arps).start()

    Thread(target = sniff_deauth).start()

    Thread(target = sniff_ns).start()

    Thread(target = sniff_na).start()
