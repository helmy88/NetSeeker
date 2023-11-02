#!/usr/bin/env python3
import scapy.all as scapy
import argparse

# ASCII art text
ascii_art = """
 _______         __   _______               __               
|    |  |.-----.|  |_|     __|.-----.-----.|  |--.-----.----.
|       ||  -__||   _|__     ||  -__|  -__||    <|  -__|   _|
|__|____||_____||____|_______||_____|_____||__|__|_____|__|
"""

# Display the ASCII art
print(ascii_art)

# Author
print("Developed by Perthlis\n")

def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices_list = []
        for element in answered_list:
            device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices_list.append(device_info)
        return devices_list

    except Exception as e:
        print("Error: ", str(e))
        return []

def scan_ports(target_ip, port_range):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 18:
            open_ports.append(port)
    return open_ports

def print_result(devices, open_ports):
    print("Active Devices:")
    print("IP Address\t\tMAC Address")
    print("----------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")
    print("\nOpen Ports:")
    print("Port")
    print("----")
    for port in open_ports:
        print(port)

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("target_ips", help="Target IP addresses (comma-separated)")
    parser.add_argument("port_range", help="Port range (e.g., 1-100)")
    options = parser.parse_args()
    return options

options = get_arguments()
target_ips = options.target_ips.split(',')
port_range = [int(port) for port in options.port_range.split('-')]

if not target_ips or len(port_range) != 2:
    print("[-] Please specify one or more target IP addresses (comma-separated) and a valid port range. Use --help for more info.")
else:
    for target_ip in target_ips:
        devices = scan(target_ip)
        open_ports = scan_ports(target_ip, port_range)
        print_result(devices, open_ports)
