"""
NetSentinel - SQL Injection Test PCAP Generator

Creates synthetic HTTP traffic containing:
1. UNION SELECT SQL injection pattern
2. OR 1=1 SQL injection pattern
3. A normal HTTP request as a control

This script does not contact any real server.
"""

from datetime import datetime, timezone
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUTPUT_FILE = "sample-data/sqli_test.pcap"

CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"

CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"

SERVER_PORT = 80

packets = []


def add_packet(packet, offset):
    """Give packets deterministic timestamps."""
    packet.time = (
        datetime.now(timezone.utc).timestamp() + offset
    )
    packets.append(packet)


def create_http_flow(
    source_port,
    request_path,
    flow_number,
    offset
):
    """
    Build a basic TCP handshake followed by an HTTP GET.
    """

    client_seq = 1000 + flow_number * 10000
    server_seq = 5000 + flow_number * 10000

    client = Ether(
        src=CLIENT_MAC,
        dst=SERVER_MAC
    ) / IP(
        src=CLIENT_IP,
        dst=SERVER_IP
    )

    server = Ether(
        src=SERVER_MAC,
        dst=CLIENT_MAC
    ) / IP(
        src=SERVER_IP,
        dst=CLIENT_IP
    )

    # 1. TCP SYN
    syn = client / TCP(
        sport=source_port,
        dport=SERVER_PORT,
        flags="S",
        seq=client_seq
    )

    add_packet(syn, offset)

    # 2. TCP SYN-ACK
    syn_ack = server / TCP(
        sport=SERVER_PORT,
        dport=source_port,
        flags="SA",
        seq=server_seq,
        ack=client_seq + 1
    )

    add_packet(syn_ack, offset + 0.001)

    # 3. TCP ACK
    ack = client / TCP(
        sport=source_port,
        dport=SERVER_PORT,
        flags="A",
        seq=client_seq + 1,
        ack=server_seq + 1
    )

    add_packet(ack, offset + 0.002)

    # 4. HTTP GET request
    http_request = (
        f"GET {request_path} HTTP/1.1\r\n"
        f"Host: demo.netsentinel.local\r\n"
        f"User-Agent: NetSentinel-Test-Client\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    payload = http_request.encode("ascii")

    request = client / TCP(
        sport=source_port,
        dport=SERVER_PORT,
        flags="PA",
        seq=client_seq + 1,
        ack=server_seq + 1
    ) / Raw(load=payload)

    add_packet(request, offset + 0.003)

    # 5. Server ACK
    response_ack = server / TCP(
        sport=SERVER_PORT,
        dport=source_port,
        flags="A",
        seq=server_seq + 1,
        ack=client_seq + 1 + len(payload)
    )

    add_packet(response_ack, offset + 0.004)


def main():
    print("Generating NetSentinel SQL injection test traffic...")

    # Test 1: UNION SELECT pattern
    create_http_flow(
        source_port=45001,
        request_path=(
            "/search?q=1%20UNION%20SELECT%20"
            "username,password%20FROM%20users"
        ),
        flow_number=1,
        offset=0
    )

    # Test 2: OR 1=1 pattern
    create_http_flow(
        source_port=45002,
        request_path=(
            "/login?user=admin%20or%201=1"
        ),
        flow_number=2,
        offset=1
    )

    # Test 3: Normal request (control)
    create_http_flow(
        source_port=45003,
        request_path="/products?id=25",
        flow_number=3,
        offset=2
    )

    packets.sort(key=lambda packet: float(packet.time))

    wrpcap(OUTPUT_FILE, packets)

    print("\nPCAP generated successfully.")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Total packets: {len(packets)}")
    print("Test flows: 3")
    print("SQL injection-pattern requests: 2")
    print("Normal control requests: 1")


if __name__ == "__main__":
    main()