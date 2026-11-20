
from scapy.all import Ether, IP, TCP, wrpcap

packets = []

# New source IP to generate unique test events
source_ip = "192.168.1.103"
destination_ip = "192.168.1.10"

test_ports = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443, 445,
    3306, 3389, 5432, 8080, 8443
]

for port in test_ports:
    packet = (
        Ether()
        / IP(src=source_ip, dst=destination_ip)
        / TCP(sport=51000 + port, dport=port, flags="S")
    )
    packets.append(packet)

output_file = "sample-data/port_scan_test_4.pcap"
wrpcap(output_file, packets)

print("NetSentinel second test PCAP generated successfully!")
print(f"Total packets: {len(packets)}")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"Output: {output_file}")
