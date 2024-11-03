# sniffer.py
import streamlit as st
from scapy.all import sniff

# Function to process packets
def packet_callback(packet):
    st.write(packet.summary())  # Display the packet summary in Streamlit

# Streamlit UI
st.title("Packet Sniffer")
st.write("Click the button to start sniffing packets:")

if st.button("Start Sniffing"):
    st.write("Sniffing... Click to stop.")
    try:
        sniff(prn=packet_callback, store=0)  # Start sniffing packets
    except Exception as e:
        st.write("Error:", e)
