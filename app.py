import streamlit as st
from scapy.all import sniff, IP, TCP, UDP, Raw
import pandas as pd
from datetime import datetime
import threading
capture_thread = threading.Thread(target=capture_packets, args=(packet_count,))


# Create a DataFrame to store packet details
packet_data = []

# Function to capture and process packets
def capture_packets(packet_count):
    def process_packet(packet):
        packet_info = {}
        
        # Capture basic IP information
        if IP in packet:
            packet_info["Time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            packet_info["Source IP"] = packet[IP].src
            packet_info["Destination IP"] = packet[IP].dst
            packet_info["Protocol"] = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            packet_info["Length"] = len(packet)
            packet_info["Payload"] = packet[Raw].load if Raw in packet else None
            packet_data.append(packet_info)
    
    # Sniff packets
    sniff(count=packet_count, prn=process_packet, store=False)

# Function to start packet capturing in a separate thread
def start_packet_capture(packet_count):
    packet_data.clear()  # Clear any previous data
    capture_thread = threading.Thread(target=capture_packets, args=(packet_count,))
    capture_thread.start()
    capture_thread.join()

# Streamlit UI setup
st.title("🔍 Network Packet Sniffer")
st.write("This tool captures network packets on your local machine. Use it strictly for educational purposes and only on networks where you have permission.")

# Sidebar to select the number of packets to capture
packet_count = st.sidebar.slider("Number of packets to capture", min_value=1, max_value=100, value=10)
capture_button = st.sidebar.button("Start Capture")

# Start packet capture
if capture_button:
    st.write(f"Capturing {packet_count} packets...")
    start_packet_capture(packet_count)
    st.success("Packet capture complete!")

    # Display captured packets in a table format
    if packet_data:
        df = pd.DataFrame(packet_data)
        st.subheader("Captured Packets")
        st.dataframe(df)
    else:
        st.write("No packets captured.")
