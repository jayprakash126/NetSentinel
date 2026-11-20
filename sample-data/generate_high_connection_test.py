from scapy.all import Ether, IP, TCP, wrpcap

packets = []

source_ip = "192.168.1.180"
destination_ip = "192.168.1.10"

# Generate 110 TCP SYN packets targeting 110 unique ports
for i in range(110):
    packet = (
        Ether()
        / IP(src=source_ip, dst=destination_ip)
        / TCP(
            sport=40000 + i,
            dport=20000 + i,
            flags="S"
        )
    )
    packets.append(packet)

output_file = "sample-data/high_connection_rate_test.pcap"

wrpcap(output_file, packets)

print("NetSentinel High Connection Rate test PCAP generated!")
print(f"Total packets: {len(packets)}")
print(f"Unique destination ports: 110")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"Output: {output_file}")