# Import necessary libraries
from scapy.all import sniff, IP, TCP, UDP, Raw
from IPython.display import display, clear_output

# Global variable to store packets
packets = []

def packet_callback(packet):
    """Callback function to process and analyze each packet."""
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        payload = packet[Raw].load if Raw in packet else None

        packet_info = {
            "Source IP": ip_layer.src,
            "Destination IP": ip_layer.dst,
            "Protocol": protocol,
            "Payload": payload
        }
        packets.append(packet_info)
        
        # Display captured packets in real-time
        display_captured_packets()

def display_captured_packets():
    """Display captured packets in a structured format."""
    clear_output(wait=True)
    print("Captured Packets:")
    for idx, packet in enumerate(packets, start=1):
        print(f"\nPacket #{idx}")
        print(f"Source IP: {packet['Source IP']}")
        print(f"Destination IP: {packet['Destination IP']}")
        print(f"Protocol: {packet['Protocol']}")
        print(f"Payload: {packet['Payload']}\n")

def start_sniffing():
    """Start sniffing packets."""
    sniff(prn=packet_callback, store=0, count=50)  # Adjust count or set to 0 for continuous

# Start sniffing
print("Starting packet sniffing... (use with caution and ethical considerations)")
print("This is an educational tool. Ensure you have permission to capture network packets.")

# Run the sniffing function
start_sniffing()

# Display final captured packets if the notebook stops
display_captured_packets()


