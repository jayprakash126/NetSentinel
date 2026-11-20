from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

packets = []

source_ip = "192.168.1.170"
destination_ip = "8.8.8.8"

# Normal DNS queries
normal_domains = [
    "google.com",
    "example.com",
    "thdc-ihet.ac.in"
]

for domain in normal_domains:
    packet = (
        IP(src=source_ip, dst=destination_ip)
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname=domain)
        )
    )
    packets.append(packet)

# Suspiciously long DNS query
long_domain = "a" * 60 + "." + "b" * 30 + ".example.com"

packet = (
    IP(src=source_ip, dst=destination_ip)
    / UDP(sport=53001, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname=long_domain)
    )
)

packets.append(packet)

output_file = "sample-data/dns_test.pcap"

wrpcap(output_file, packets)

print("DNS test PCAP generated successfully!")
print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"Total DNS queries: {len(packets)}")
print(f"Suspicious domain: {long_domain}")
print(f"Output file: {output_file}")