
# Importing libraries
import streamlit as st
from scapy.all import sniff, IP, TCP, UDP, Ether
from datetime import datetime

# Display header
st.title("🔍 Educational Packet Sniffer")
st.write("This packet sniffer captures network traffic on your local machine. Ensure it's used for educational purposes only.")

# Sidebar controls
num_packets = st.sidebar.slider("Number of packets to capture", min_value=1, max_value=100, value=10)
protocol_filter = st.sidebar.selectbox("Filter by protocol", ["All", "TCP", "UDP", "ICMP"])
start_sniffing = st.sidebar.button("Start Packet Capture")

# Function to analyze packet
def packet_analysis(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
    else:
        ip_src = ip_dst = protocol = None
    
    # Display protocol details
    if protocol == 6:
        protocol_name = "TCP"
        payload = bytes(packet[TCP].payload) if TCP in packet else None
    elif protocol == 17:
        protocol_name = "UDP"
        payload = bytes(packet[UDP].payload) if UDP in packet else None
    else:
        protocol_name = "Other"
        payload = bytes(packet.payload)
    
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source IP": ip_src,
        "Destination IP": ip_dst,
        "Protocol": protocol_name,
        "Payload": payload,
    }

# Packet capture and display
if start_sniffing:
    st.write(f"Capturing {num_packets} packets...")

    # Filter function for packet sniffing
    def custom_filter(packet):
        if protocol_filter == "All":
            return True
        elif protocol_filter == "TCP" and TCP in packet:
            return True
        elif protocol_filter == "UDP" and UDP in packet:
            return True
        elif protocol_filter == "ICMP" and IP in packet and packet[IP].proto == 1:
            return True
        return False

    # Start packet sniffing
    packets = sniff(count=num_packets, lfilter=custom_filter)
    st.success("Packet capture complete!")

    # Display captured packets
    for packet in packets:
        packet_info = packet_analysis(packet)
        with st.expander(f"Packet from {packet_info['Source IP']} to {packet_info['Destination IP']}"):
            st.write("Timestamp:", packet_info["Timestamp"])
            st.write("Source IP:", packet_info["Source IP"])
            st.write("Destination IP:", packet_info["Destination IP"])
            st.write("Protocol:", packet_info["Protocol"])
            st.write("Payload:", packet_info["Payload"])
else:
    st.write("Click 'Start Packet Capture' to begin capturing packets.")
