
from scapy.all import IP, UDP, Raw, wrpcap
from datetime import datetime

packets = []

source_ip = "192.168.1.150"
destination_ip = "192.168.1.10"

# Generate 25 UDP packets targeting different ports
for port in range(1000, 1025):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / UDP(sport=40000 + port % 1000, dport=port)
        / Raw(load="NetSentinel UDP scan test")
    )

    packets.append(packet)

output_file = "sample-data/udp_port_scan_test.pcap"

wrpcap(output_file, packets)

print("UDP scan test PCAP generated successfully!")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"UDP packets generated: {len(packets)}")
print(f"Output file: {output_file}")
