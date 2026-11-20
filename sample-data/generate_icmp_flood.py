
from scapy.all import IP, ICMP, Raw, wrpcap

packets = []

source_ip = "192.168.1.160"
destination_ip = "192.168.1.10"

# Generate 100 ICMP Echo Request packets
for sequence in range(1, 101):
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / ICMP(type=8, code=0, id=1234, seq=sequence)
        / Raw(load="NetSentinel ICMP flood test")
    )

    packets.append(packet)

output_file = "sample-data/icmp_flood_test.pcap"

wrpcap(output_file, packets)

print("ICMP flood test PCAP generated successfully!")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"ICMP packets generated: {len(packets)}")
print(f"Output file: {output_file}")
