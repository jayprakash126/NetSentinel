
from datetime import datetime, timezone
from pathlib import Path

from scapy.utils import RawPcapReader, PcapWriter
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


# ==========================================
# NetSentinel - One-Click Dataset Extractor
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SOURCE_PCAP = (
    PROJECT_ROOT
    / "sample-data"
    / "external-datasets"
    / "CIC-IDS2017"
    / "Thursday"
    / "Thursday-WorkingHours.pcap"
)

OUTPUT_PCAP = (
    PROJECT_ROOT
    / "sample-data"
    / "external-datasets"
    / "CIC-IDS2017"
    / "processed"
    / "sql-injection"
    / "attack.pcap"
)

START_TIME = "2017-07-06T13:35:00"
END_TIME = "2017-07-06T13:44:00"

SOURCE_IP = "172.16.0.1"
DESTINATION_IP = "192.168.10.50"

PROTOCOL = "tcp"
PORT = 80


def parse_time(value):
    dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def extract_packets():

    print("\n==========================================")
    print("       NetSentinel Dataset Extractor")
    print("==========================================")

    if not SOURCE_PCAP.is_file():
        raise FileNotFoundError(
            f"Source PCAP not found:\n{SOURCE_PCAP}"
        )

    if SOURCE_PCAP.resolve() == OUTPUT_PCAP.resolve():
        raise ValueError("Input and output files must be different.")

    start = parse_time(START_TIME)
    end = parse_time(END_TIME)

    if start >= end:
        raise ValueError("Invalid extraction time window.")

    OUTPUT_PCAP.parent.mkdir(parents=True, exist_ok=True)

    reader = RawPcapReader(str(SOURCE_PCAP))
    writer = None

    scanned = 0
    selected = 0

    try:
        writer = PcapWriter(
            str(OUTPUT_PCAP),
            linktype=1,
            sync=True
        )

        print("\nScanning source dataset...")
        print("Please wait. The original PCAP is several GB in size.\n")

        for raw, meta in reader:

            scanned += 1

            timestamp = (
                ((meta.tshigh << 32) | meta.tslow)
                / meta.tsresol
            )

            if not start <= timestamp <= end:
                continue

            try:
                packet = Ether(raw)

                if IP not in packet:
                    continue

                ip = packet[IP]

                if PROTOCOL == "tcp" and TCP not in packet:
                    continue

                if SOURCE_IP and DESTINATION_IP:
                    forward = (
                        ip.src == SOURCE_IP
                        and ip.dst == DESTINATION_IP
                    )

                    reverse = (
                        ip.src == DESTINATION_IP
                        and ip.dst == SOURCE_IP
                    )

                    if not (forward or reverse):
                        continue

                if PORT:
                    if TCP not in packet:
                        continue

                    if (
                        packet[TCP].sport != PORT
                        and packet[TCP].dport != PORT
                    ):
                        continue

                packet.time = timestamp
                writer.write(packet)

                selected += 1

            except Exception:
                continue

    finally:
        reader.close()

        if writer:
            writer.close()

    print("\n==========================================")
    print("           EXTRACTION COMPLETE")
    print("==========================================")
    print(f"Source PCAP:       {SOURCE_PCAP.name}")
    print(f"Output PCAP:       {OUTPUT_PCAP.name}")
    print(f"Packets scanned:   {scanned:,}")
    print(f"Packets extracted: {selected:,}")
    print(f"Output size:       {OUTPUT_PCAP.stat().st_size / (1024**2):.2f} MB")
    print("==========================================\n")


if __name__ == "__main__":
    try:
        extract_packets()
    except Exception as error:
        print(f"\nEXTRACTION FAILED: {error}")
