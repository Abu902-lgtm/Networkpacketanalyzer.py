import streamlit as st
from scapy.all import sniff
import threading

# Function to process packets
def packet_callback(packet):
    # Use session state to store packets
    if 'packets' not in st.session_state:
        st.session_state.packets = []
    st.session_state.packets.append(packet.summary())  # Store packet summary

# Function to start sniffing in a separate thread
def start_sniffing():
    st.write("Sniffing... Click to stop.")
    sniff(prn=packet_callback, store=0)  # Start sniffing packets

# Streamlit UI
st.title("Packet Sniffer")
st.write("Click the button to start sniffing packets:")

if st.button("Start Sniffing"):
    # Start sniffing in a separate thread
    threading.Thread(target=start_sniffing).start()

# Display captured packets
if 'packets' in st.session_state:
    st.write("Captured Packets:")
    for packet in st.session_state.packets:
        st.write(packet)

