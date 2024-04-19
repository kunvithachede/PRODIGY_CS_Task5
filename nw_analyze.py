from scapy.all import sniff
def packet_handler(packet):
    if packet.haslayer("IP"):  
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        proto = packet["IP"].proto

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            print(f"Payload: {payload.hex()}")

# Start sniffing packets
print("Sniffing started... (Press Ctrl+C to stop)")
sniff(prn=packet_handler, store=0)
