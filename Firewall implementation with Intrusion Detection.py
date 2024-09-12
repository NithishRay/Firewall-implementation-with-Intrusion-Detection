from scapy.all import *
from datetime import datetime
import threading

# List of allowed IPs and ports (for packet filtering)
allowed_ips = ["192.168.1.1", "192.168.1.2"]
allowed_ports = [22, 80, 443]

# List to track port scan activity
scan_detected = {}


# Function to log traffic
def log_traffic(action, packet):
    with open("firewall_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {action} - {packet.summary()}\n")


# Function to check if the packet is allowed based on the firewall rules
def packet_filter(packet):
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip not in allowed_ips:
            log_traffic("BLOCKED (IP)", packet)
            return False

    if TCP in packet:
        dest_port = packet[TCP].dport
        if dest_port not in allowed_ports:
            log_traffic("BLOCKED (PORT)", packet)
            return False

    log_traffic("ALLOWED", packet)
    return True


# Function to detect port scans
def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dest_port = packet[TCP].dport

        # Track port scan activity
        if src_ip not in scan_detected:
            scan_detected[src_ip] = set()

        scan_detected[src_ip].add(dest_port)

        # If more than 5 ports are targeted from the same IP in a short period
        if len(scan_detected[src_ip]) > 5:
            print(f"[!] Port scan detected from {src_ip}")
            log_traffic("PORT SCAN DETECTED", packet)


# Function to process each packet
def process_packet(packet):
    if packet_filter(packet):
        detect_port_scan(packet)


# Sniffer thread to handle packets asynchronously
def sniff_packets():
    sniff(prn=process_packet, store=0)


# Start the firewall in real-time
def start_firewall():
    print("Real-Time Firewall started... Monitoring traffic")
    # Run the sniffing process in a separate thread
    sniffer_thread = threading.Thread(target=sniff_packets)
    sniffer_thread.daemon = True  # Allows the thread to exit when the main program exits
    sniffer_thread.start()

    # Keep the main program running for real-time monitoring
    try:
        while True:
            pass  # Keep the program alive
    except KeyboardInterrupt:
        print("Firewall stopped.")


if __name__ == "__main__":
    start_firewall()
