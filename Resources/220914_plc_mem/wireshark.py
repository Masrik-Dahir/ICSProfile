import sys
import os
import json
import pyshark
import binascii
import socket
import struct
from datetime import datetime

def extract_packet_data(pcap_file):
    packets_info = []
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    for packet in cap:
        packet_data = {}
        packet_data["Timestamp"] = str(packet.sniff_time)
        raw_packet = binascii.hexlify(bytes.fromhex(packet.frame_raw.value)).decode() if hasattr(packet,
                                                                                                 'frame_raw') else ""

        # Store only raw packet data
        packet_data["Raw_Packet_Data"] = raw_packet

        if raw_packet:
            packets_info.append(packet_data)

    cap.close()
    return packets_info


def process_pcap_directory(pcap_dir, output_file):
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcapng')]
    all_packets = []

    for pcap_file in pcap_files:
        file_path = os.path.join(pcap_dir, pcap_file)
        print(f"Processing {file_path}...")
        packets = extract_packet_data(file_path)
        all_packets.extend(packets)

    output = {"Packets": all_packets}

    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)
    print(f"Packet data exported to {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PCAP Packet Extractor")
    parser.add_argument("--pcap-dir", help="Directory containing PCAPNG files", required=True)
    parser.add_argument("--output-file", help="Output file name for extracted packet data", default="packet_data.json")
    args = parser.parse_args()

    process_pcap_directory(args.pcap_dir, args.output_file)


if __name__ == "__main__":
    main()
