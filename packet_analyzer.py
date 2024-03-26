import socket
from scapy.all import *
import pywifi
from pywifi import *

def port_scanner(target, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open.")
            s.close()
        except KeyboardInterrupt:
            print("\nExiting")
            exit()
        except Exception as e:
            print(f"Error: {e}")
            pass
    return open_ports

def packet_sniffer(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

def analyze_packets(packets):
    print("\nAnalysis of captured packets")
    for packet in packets:
        print(packet)

def wifi_analyzer():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    results = iface.scan_results()
    print("\nWi-Fi Networks:")
    for result in results:
        print(f"SSID: {result.ssid} | BSSID: {result.bssid} | Signal Strength: {result.signal}")

target = input("Enter target IP Address: ")
start_port = int(input("Enter starting Port Number: "))
end_port = int(input("Enter ending Port Number: "))
count = int(input("Enter number of Packets to Sniff: "))

print("\nScanning for open ports")
open_ports = port_scanner(target, start_port, end_port)
if open_ports:
    print(f"Open ports: {open_ports}")
else:
    print("No open ports found.")

print("\nSniffing network traffic")
packets = packet_sniffer(None,count)

if packets:
    analyze_packets(packets)
else:
    print("No packets captured.")

wifi_analyzer()
