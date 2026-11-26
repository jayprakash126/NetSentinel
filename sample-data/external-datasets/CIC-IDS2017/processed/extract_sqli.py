from scapy.utils import RawPcapReader, PcapWriter
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from datetime import datetime, timezone
from pathlib import Path

source = Path(r"sample-data/external-datasets/CIC-IDS2017/Thursday/Thursday-WorkingHours.pcap")
output = Path(r"sample-data/external-datasets/CIC-IDS2017/processed/thursday_sqli_candidate.pcap")

start = datetime(2017, 7, 6, 13, 35, tzinfo=timezone.utc).timestamp()
end = datetime(2017, 7, 6, 13, 44, tzinfo=timezone.utc).timestamp()

reader = RawPcapReader(str(source))
writer = PcapWriter(str(output), linktype=1, sync=True)
selected = 0

try:
    for raw, meta in reader:
        timestamp = ((meta.tshigh << 32) | meta.tslow) / meta.tsresol

        if not start <= timestamp <= end:
            continue

        try:
            packet = Ether(raw)

            if IP not in packet or TCP not in packet:
                continue

            ip = packet[IP]
            tcp = packet[TCP]

            forward = (
                ip.src == "172.16.0.1"
                and ip.dst == "192.168.10.50"
                and tcp.dport == 80
            )

            reverse = (
                ip.src == "192.168.10.50"
                and ip.dst == "172.16.0.1"
                and tcp.sport == 80
            )

            if forward or reverse:
                packet.time = timestamp
                writer.write(packet)
                selected += 1

        except Exception:
            continue

finally:
    reader.close()
    writer.close()

print("Extraction complete.")
print("Selected packets:", selected)
print("Output:", output)
