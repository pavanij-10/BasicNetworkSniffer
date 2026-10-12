
from scapy.all import sniff, rdpcap, wrpcap, IP, TCP, UDP, ICMP, DNS, Raw
from collections import Counter
import ipaddress
import os

def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return "Other"

def analyze_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    protocol = get_protocol(packet)

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        explanation = "TCP provides reliable, ordered data delivery."
    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        explanation = "UDP sends datagrams without guaranteeing delivery."
    elif ICMP in packet:
        source_port = "-"
        destination_port = "-"
        explanation = "ICMP carries network control and diagnostic messages."
    else:
        source_port = "-"
        destination_port = "-"
        explanation = "Another IPv4 protocol was detected."

    if DNS in packet:
        explanation += " DNS data was identified."

    layers = [layer.__name__ for layer in packet.layers()]

    print("-" * 55)
    print(f"Source IP        : {ip.src}")
    print(f"Destination IP   : {ip.dst}")
    print(f"Protocol         : {protocol}")
    print(f"Source Port      : {source_port}")
    print(f"Destination Port : {destination_port}")
    print(f"Packet Size      : {len(packet)} bytes")
    print(f"Packet Layers    : {' -> '.join(layers)}")
    print(f"Explanation      : {explanation}")

    if Raw in packet:
        print(f"Payload Size     : {len(bytes(packet[Raw].load))} bytes")
        print("Payload Preview  : Hidden by default")

def choose_filters():
    print("\nProtocol filter")
    print("1. All IPv4 traffic")
    print("2. TCP")
    print("3. UDP")
    print("4. ICMP")

    choices = {"1": "All", "2": "TCP", "3": "UDP", "4": "ICMP"}
    choice = input("Choose a filter (1-4): ").strip()

    if choice not in choices:
        print("Invalid protocol choice.")
        return None, None

    selected_protocol = choices[choice]
    selected_ip = input("Filter by IP address (Enter to skip): ").strip()

    if selected_ip:
        try:
            ipaddress.IPv4Address(selected_ip)
        except ipaddress.AddressValueError:
            print("Invalid IPv4 address.")
            return None, None

    return selected_protocol, selected_ip or None

def matches_filters(packet, protocol, ip_address):
    if IP not in packet:
        return False

    if protocol != "All" and get_protocol(packet) != protocol:
        return False

    if ip_address and ip_address not in (packet[IP].src, packet[IP].dst):
        return False

    return True

def get_packet_limit():
    value = input("Maximum matching packets (default 20): ").strip()

    try:
        limit = int(value) if value else 20
        if limit < 1:
            raise ValueError
        return limit
    except ValueError:
        print("Enter a positive whole number.")
        return None

def show_summary(packets):
    counts = Counter(get_protocol(packet) for packet in packets)
    total_bytes = sum(len(packet) for packet in packets)

    print("\nCAPTURE SUMMARY")
    print("-" * 30)
    print(f"Packets analyzed: {len(packets)}")
    print(f"Total data size : {total_bytes} bytes")

    for protocol, number in counts.items():
        print(f"{protocol:10}: {number}")

def live_capture():
    protocol, ip_address = choose_filters()
    if protocol is None:
        return

    limit = get_packet_limit()
    if limit is None:
        return

    bpf_filters = {
        "All": "ip",
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp"
    }

    capture_filter = bpf_filters[protocol]
    if ip_address:
        capture_filter += f" and host {ip_address}"

    packets = []

    def receive(packet):
        if matches_filters(packet, protocol, ip_address):
            packets.append(packet)
            analyze_packet(packet)

    print(f"\nStarting live capture: {capture_filter}")
    print("Inspect only traffic you are authorized to capture.")

    try:
        sniff(
            filter=capture_filter,
            prn=receive,
            stop_filter=lambda packet: len(packets) >= limit,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as error:
        print(f"Capture error: {error}")
    finally:
        if packets:
            output_file = "captured_packets.pcap"
            wrpcap(output_file, packets)
            show_summary(packets)
            print(f"Saved matching packets to: {os.path.abspath(output_file)}")
        else:
            print("No matching packets were captured.")

def replay_pcap():
    filename = input("Enter PCAP file path: ").strip().strip('"')

    if not os.path.isfile(filename):
        print("File not found.")
        return

    try:
        saved_packets = rdpcap(filename)
    except Exception as error:
        print(f"Could not read PCAP file: {error}")
        return

    protocol, ip_address = choose_filters()
    if protocol is None:
        return

    limit = get_packet_limit()
    if limit is None:
        return

    matching_packets = [
        packet for packet in saved_packets
        if matches_filters(packet, protocol, ip_address)
    ][:limit]

    if not matching_packets:
        print("No packets matched your filters.")
        return

    print(f"\nAnalyzing saved file: {filename}")
    print(f"Matching packets found: {len(matching_packets)}")

    for packet in matching_packets:
        analyze_packet(packet)

    show_summary(matching_packets)
    print("Original PCAP file was not modified.")

def main():
    while True:
        print("\nBASIC NETWORK SNIFFER")
        print("1. Capture live traffic")
        print("2. Analyze saved PCAP file")
        print("3. Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            live_capture()
        elif choice == "2":
            replay_pcap()
        elif choice == "3":
            print("Exiting sniffer.")
            break
        else:
            print("Invalid choice. Select 1, 2, or 3.")

if __name__ == "__main__":
    main()
