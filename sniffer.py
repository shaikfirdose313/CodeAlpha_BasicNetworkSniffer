from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def analyze_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*60}")
    print(f"[{timestamp}] Packet Captured")

    # Check if IP layer exists
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        proto_name = {1:"ICMP", 6:"TCP", 17:"UDP"}.get(protocol, f"Other({protocol})")

        print(f"Source IP : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol : {proto_name}")

        # Port info for TCP/UDP
        if TCP in packet:
            print(f"Source Port : {packet[TCP].sport} -> Dest Port: {packet[TCP].dport}")
            print(f"Flags : {packet[TCP].flags}")
        elif UDP in packet:
            print(f"Source Port : {packet[UDP].sport} -> Dest Port: {packet[UDP].dport}")

        # Payload
        if Raw in packet:
            try:
                payload = packet[Raw].load
                # show only first 200 bytes to be clean
                print(f"Payload (first 200 bytes): {payload[:200]}")
            except:
                print("Payload: Unable to decode")
    else:
        print(f"Non-IP Packet: {packet.summary()}")

def main():
    print("=== CodeAlpha - Basic Network Sniffer ===")
    print("Starting sniffer... Press CTRL+C to stop.\n")
    print("NOTE: Use only on your own network for educational purpose.")

    try:
        # count=0 means infinite, filter can be "tcp", "udp", "icmp"
        # change iface to None for default interface
        sniff(prn=analyze_packet, store=False, count=20) # captures 20 packets for demo
        # For continuous: sniff(prn=analyze_packet, store=False)
    except PermissionError:
        print("Error: Run as Administrator / sudo")
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")

if __name__ == "__main__":
    main()