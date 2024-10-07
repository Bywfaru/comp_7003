from scapy.all import sniff
import sys

# Dictionary matching EtherTypes to their hex code
ETHER_TYPES = {
    "ipv4": "0800",
    "ipv6": "08dd",
    "arp": "0806"
}

# Dictionary matching protocols to their IPv4 hex code
IPV4_PROTOCOLS = {
    "tcp": "06",
    "udp": "11"
}

# Generator for counting how many packets have been processed
def increment_packet_count():
    packet_count = 0

    while True:
        packet_count += 1

        yield packet_count

# Create an instance of the generator
packet_count_generator = increment_packet_count()

# Convert hex value to readable MAC address
def hex_to_readable_mac_address(hex_value):
    return ':'.join(hex_value[i:i + 2] for i in range(0, 12, 2)).upper()

# Prints the original hex value and its  decimal value
def print_hex_and_decimal(hex_value):
    print(f"- Hex: {hex_value.upper()}")
    print(f"- Decimal: {int(hex_value, 16)}")

# Converts hext value to readable MAC address, then prints it
def print_readable_mac_address(hex_value):
    print(f"- Readable: {hex_to_readable_mac_address(hex_value)}")

# Parses TCP header frame and prints out the result
def parse_tcp_frame(hex_data):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    sequence_number = hex_data[76:84]
    acknowledgement_number = hex_data[84:92]
    data_offset_reserved_and_flags = hex_data[92:96]
    window_size = hex_data[96:100]
    checksum = hex_data[100:104]
    urgent_pointer = hex_data[104:108]

    # Convert from hex to binary, then pad with 0s until we have 16 bits
    data_offset_reserved_and_flags_binary = bin(int(data_offset_reserved_and_flags, 16)).zfill(16)
    # Flags are the last 9 bits
    flags = data_offset_reserved_and_flags_binary[-9:]
    urg = flags[0]
    ack = flags[1]
    psh = flags[2]
    rst = flags[3]
    syn = flags[4]
    fin = flags[5]
    ece = flags[6]
    cwr = flags[7]
    ns = flags[8]

    print("- TCP header frame -----------------------------------")
    print("Source Port:")
    print_hex_and_decimal(source_port)
    print("Destination Port:")
    print_hex_and_decimal(destination_port)
    print("Sequence Number:")
    print_hex_and_decimal(sequence_number)
    print("Acknowledgement Number:")
    print_hex_and_decimal(acknowledgement_number)
    print("Data Offset, Reserved, and Flags:")
    print_hex_and_decimal(data_offset_reserved_and_flags)
    print("- Flags:")
    print(f"  - Urgent: {urg}")
    print(f"  - Acknowledgement: {ack}")
    print(f"  - Push: {psh}")
    print(f"  - Reset: {rst}")
    print(f"  - Synchronize: {syn}")
    print(f"  - Finish: {fin}")
    print(f"  - Explicit Congestion Notification Echo: {ece}")
    print(f"  - Congestion Window Reduced: {cwr}")
    print(f"  - Nonce Sum: {ns}")
    print("Window:")
    print_hex_and_decimal(window_size)
    print("Checksum:")
    print_hex_and_decimal(checksum)
    print("Urgent Pointer:")
    print_hex_and_decimal(urgent_pointer)

# Parse UDP header frame
def parse_udp_frame(hex_data):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    length = hex_data[76:80]
    checksum = hex_data[80:84]

    print("- UDP header frame -----------------------------------")
    print("Source Port:")
    print_hex_and_decimal(source_port)
    print("Destination Port:")
    print_hex_and_decimal(destination_port)
    print("Length:")
    print_hex_and_decimal(length)
    print("Checksum:")
    print_hex_and_decimal(checksum)

# Parse ARP header frame
def parse_arp_frame(hex_data):
    hardware_type = hex_data[28:32]
    protocol_type = hex_data[32:36]
    hardware_size = hex_data[36:38]
    protocol_size = hex_data[38:40]
    opcode = hex_data[40:44]
    sender_mac_address = hex_data[44:56]
    sender_ip_address = hex_data[56:64]
    target_mac_address = hex_data[64:76]
    target_ip_address = hex_data[76:84]

    print("- ARP header frame -----------------------------------")
    print("Hardware Type:")
    print_hex_and_decimal(hardware_type)
    print("Protocol Type:")
    print_hex_and_decimal(protocol_type)
    print("Hardware Size:")
    print_hex_and_decimal(hardware_size)
    print("Protocol Size:")
    print_hex_and_decimal(protocol_size)
    print("Opcode:")
    print_hex_and_decimal(opcode)
    print("Sender MAC Address:")
    print_hex_and_decimal(sender_mac_address)
    print_readable_mac_address(sender_mac_address)
    print("Sender IP Address:")
    print_hex_and_decimal(sender_ip_address)
    print("Target MAC Address:")
    print_hex_and_decimal(target_mac_address)
    print_readable_mac_address(target_mac_address)
    print("Target IP Address:")
    print_hex_and_decimal(target_ip_address)

# Parse IPv4 header frame
def parse_ipv4_frame(hex_data):
    internet_protocol_version = hex_data[28:29]
    internet_header_length = hex_data[29:30]
    type_of_service = hex_data[30:32]
    total_length = hex_data[32:36]
    identification = hex_data[36:40]
    flags_and_fragment_offset = hex_data[40:44]
    time_to_live = hex_data[44:46]
    protocol = hex_data[46:48]
    header_checksum = hex_data[48:52]
    source_ip_address = hex_data[52:60]
    destination_ip_address = hex_data[60:68]

    # Convert from hex to binary, then pad with 0s until we have 16 bits
    flags_and_fragment_offset_binary = bin(int(flags_and_fragment_offset, 16)).zfill(16)
    # Flags are the first 3 bits
    flags = flags_and_fragment_offset_binary[0:3]
    res = flags[0]
    dfe = flags[1]
    mfe = flags[2]

    print("- IPv4 header frame ----------------------------------")
    print("Internet Protocol Version:")
    print_hex_and_decimal(internet_protocol_version)
    print("Internet Header Length (IHL):")
    print_hex_and_decimal(internet_header_length)
    print("Type of Service:")
    print_hex_and_decimal(type_of_service)
    print("Total Length:")
    print_hex_and_decimal(total_length)
    print("Identification:")
    print_hex_and_decimal(identification)
    print("Flags and Fragment Offset:")
    print_hex_and_decimal(flags_and_fragment_offset)
    print("- Flags:")
    print(f"  - Reserved: {res}")
    print(f"  - Don't Fragment (DF): {dfe}")
    print(f"  - More Fragments (MF): {mfe}")
    print("Time to Live (TTL):")
    print_hex_and_decimal(time_to_live)
    print("Protocol:")
    print_hex_and_decimal(protocol)
    print("Header Checksum:")
    print_hex_and_decimal(header_checksum)
    print("Source IP Address:")
    print_hex_and_decimal(source_ip_address)
    print("Destination IP Address:")
    print_hex_and_decimal(destination_ip_address)

    if protocol == IPV4_PROTOCOLS["tcp"]:
        parse_tcp_frame(hex_data)
    elif protocol == IPV4_PROTOCOLS["udp"]:
        parse_udp_frame(hex_data)
    else:
        print(f"Unsupported protocol: {protocol}")

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]

    print("- Ethernet header frame ------------------------------")
    print("Destination MAC:")
    print_hex_and_decimal(dest_mac)
    print_readable_mac_address(dest_mac)
    print("Source MAC:")
    print_hex_and_decimal(source_mac)
    print_readable_mac_address(source_mac)
    print("EtherType:")
    print_hex_and_decimal(ether_type)

    if ether_type == ETHER_TYPES["ipv4"]:
        parse_ipv4_frame(hex_data)
    elif ether_type == ETHER_TYPES["arp"]:
        parse_arp_frame(hex_data)
    elif ether_type == ETHER_TYPES["ipv6"]:
        print("IPv6 header frame parsing currently not supported.")
    else:
        print(f"Unsupported EtherType: {ether_type}")

    print()

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    # Process the Ethernet header
    print(f"Captured Packet #{next(packet_count_generator)}:")
    print(f"Hex: {hex_data}")

    parse_ethernet_header(hex_data)

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting {packet_count} packet captures on {interface} with filter: {capture_filter}\n")

    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

    num_packets_captured = next(packet_count_generator) - 1

    if num_packets_captured >= 5:
        print(f"Finished capturing {packet_count} packets on {interface} with filter: {capture_filter}")
    else:
        print(f"Failed to capture {packet_count} packets. Captured {num_packets_captured}/{packet_count}")

if len(sys.argv) == 4:
    capture_packets(sys.argv[1], sys.argv[2], int(sys.argv[3]))
else:
    print(f"Invalid arguments: {sys.argv[1:]}")
    print(f"Please try again with the following format: {sys.argv[0]} <interface> <bpf_capture_filter> <packet_count>")
    print(f"Example: {sys.argv[0]} eth0 \"ip and tcp\" 5")
