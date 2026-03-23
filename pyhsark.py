import pyshark

# Load the file
cap = pyshark.FileCapture('test.pcap')

print("--- Sentinel SYN Hunter Active ---")

for packet in cap:
    try:
        # We check if the packet has a TCP layer
        if 'TCP' in packet:
            # In PyShark, flags are accessed as strings '0' or '1'
            is_syn = packet.tcp.flags_syn
            
            if is_syn == '1':
                print(f"ATTACK? -> SYN Detected from {packet.ip.src} to port {packet.tcp.dstport}")
            else:
                print(f"Normal -> ACK/Data from {packet.ip.src}")
                
    except AttributeError:
        continue

cap.close()
print("--- Analysis Complete ---")