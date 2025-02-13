import sys
import os
import json
import pyshark
import binascii
import socket
import struct
from datetime import datetime
import argparse

def extract_packet_data(pcap_file):
    raw_packets = []
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    for packet in cap:
        raw_packet = binascii.hexlify(bytes.fromhex(packet.frame_raw.value)).decode() if hasattr(packet,
                                                                                                 'frame_raw') else ""

        if raw_packet:
            raw_packets.append(raw_packet)

    cap.close()
    return raw_packets


def process_pcap_directory(pcap_dir):
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcapng')]
    all_raw_packets = []

    for pcap_file in pcap_files:
        file_path = os.path.join(pcap_dir, pcap_file)
        print(f"Processing {file_path}...")
        raw_packets = extract_packet_data(file_path)
        all_raw_packets.extend(raw_packets)

    return all_raw_packets


def get_nesting_depth(template, depth=0):
    """ Recursively determine the depth of a nested protocol template """
    if isinstance(template, dict):
        return max([get_nesting_depth(value, depth + 1) for value in template.values()] + [depth])
    return depth


def detect_protocol(transport_header: str, protocol_templates: dict) -> dict:
    """
    Detects the transport protocol and generates a JSON profile in the required format.
    Prefers templates with nested protocols before simpler ones.
    """

    transport_header = binascii.unhexlify(transport_header)

    if len(transport_header) < 2:
        return {"Protocol_Template": {"Name": "Unknown"}}  # Not enough data to analyze

    raw_packet = transport_header

    # Sort protocols to prioritize ones with nested structures (e.g., Modbus-Umas before Modbus)
    sorted_protocols = sorted(protocol_templates.items(), key=lambda x: get_nesting_depth(x[1]["Protocol_Template"]),
                              reverse=True)

    # Iterate over protocols in priority order
    for protocol_name, template in sorted_protocols:
        field_offsets = template["Protocol_Template"]

        # Filter valid offset pairs
        valid_offsets = [offsets for offsets in field_offsets.values() if isinstance(offsets, list) and len(offsets) == 2]

        # Determine if the packet length is sufficient for this protocol
        max_offset = max([end for _, end in valid_offsets], default=0)

        if len(raw_packet) < max_offset:
            continue  # Not enough data for this protocol

        # Generate the profile with offsets
        profile = {
            "Protocol_Template": {
                "Name": template["Protocol_Template"].get("Name", protocol_name)
            }
        }

        for field, offsets in field_offsets.items():
            if isinstance(offsets, list) and len(offsets) == 2:
                profile["Protocol_Template"][field] = offsets
            elif isinstance(offsets, dict):  # Handle nested protocols like UMAS
                profile["Protocol_Template"][field] = {
                    "Protocol_Template": {}
                }
                for nested_field, nested_offsets in offsets["Protocol_Template"].items():
                    profile["Protocol_Template"][field]["Protocol_Template"][nested_field] = nested_offsets
            else:
                profile["Protocol_Template"][field] = None  # Preserve structure

        return profile  # Return first matching protocol

    return {"Protocol_Template": {"Name": "Other"}}  # No match found


def save_profile_json(data, filename="profile.json"):
    """ Saves the protocol profile in the required format to a JSON file. """
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Profile saved to {filename}")


# **🔹 Updated Protocol Templates (UMAS is Nested Inside Modbus-Umas)**
protocol_templates = {
    "Modbus": {
        "Protocol_Template": {
            "Transaction_ID": [0, 2],
            "Protocol_ID": [2, 4],
            "Length": [4, 6],
            "Unit_ID": [6, 7],
            "Function_Code": [7, 8],
            "Source": None,
            "Destination": None,
            "Control": None,
            "Application_Control": None,
            "Message_Type": None,
            "Service": None,
            "Request_ID": None,
            "Response_Code": None,
            "Service_Type": None,
            "Frame_ID": None,
            "Cycle_Counter": None
        }
    },
    "Modbus-Umas": {
        "Protocol_Template": {
            "Transaction_ID": [0, 2],
            "Protocol_ID": [2, 4],
            "Length": [4, 6],
            "Unit_ID": [6, 7],
            "Function_Code": [7, 8],
            "Source": None,
            "Destination": None,
            "Control": None,
            "Application_Control": None,
            "Message_Type": None,
            "Service": None,
            "Request_ID": None,
            "Response_Code": None,
            "Service_Type": None,
            "Frame_ID": None,
            "Cycle_Counter": None,
            "UMAS": {
                "Protocol_Template": {
                    "Header": [8, 10],
                    "Subfunction": [10, 12],
                    "Session_ID": [12, 14],
                    "Device_ID": [14, 18],
                    "Request_ID": [18, 22],
                    "Command_Code": [22, 24],
                    "Status": [24, 26]
                }
            }
        }
    },
    "DNP3": {
        "Protocol_Template": {
            "Transaction_ID": None,
            "Protocol_ID": None,
            "Length": None,
            "Unit_ID": None,
            "Function_Code": [0, 2],
            "Source": [2, 6],
            "Destination": [6, 10],
            "Control": [10, 12],
            "Application_Control": [12, 14],
            "Message_Type": None,
            "Service": None,
            "Request_ID": None,
            "Response_Code": None,
            "Service_Type": None,
            "Frame_ID": None,
            "Cycle_Counter": None
        }
    },
    "OPC UA": {
        "Protocol_Template": {
            "Name": "OPC UA",
            "Transaction_ID": None,
            "Protocol_ID": None,
            "Length": None,
            "Unit_ID": None,
            "Function_Code": None,
            "Source": None,
            "Destination": None,
            "Control": None,
            "Application_Control": None,
            "Message_Type": [0, 2],
            "Service": [2, 6],
            "Request_ID": [6, 10],
            "Response_Code": [10, 14],
            "Service_Type": None,
            "Frame_ID": None,
            "Cycle_Counter": None,
            "Payload": None
        }
    },
    "Profinet": {
        "Protocol_Template": {
            "Name": "Profinet",
            "Transaction_ID": None,
            "Protocol_ID": None,
            "Length": None,
            "Unit_ID": None,
            "Function_Code": None,
            "Source": None,
            "Destination": None,
            "Control": None,
            "Application_Control": None,
            "Message_Type": None,
            "Service": None,
            "Request_ID": None,
            "Response_Code": None,
            "Service_Type": [0, 2],
            "Frame_ID": [2, 6],
            "Cycle_Counter": [6, 10],
            "Payload": None
        }
    }
}
def save_profile_json(data, filename="profile.json"):
    """ Saves the profile data in the required format to a JSON file. """
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Profile saved to {filename}")

from collections import Counter

from collections import Counter


def main():
    parser = argparse.ArgumentParser(description="PCAP Packet Extractor")
    parser.add_argument("--pcap-dir", help="Directory containing PCAPNG files", required=True)
    parser.add_argument("--output-file", help="Output file name for extracted packet data", default="profile.json")
    args = parser.parse_args()

    # Process the directory and get the raw packets
    all_raw_packets = process_pcap_directory(args.pcap_dir)

    # Dictionary to count occurrences of each detected profile
    profile_counts = Counter()

    # **🔹 Test protocol detection for each raw packet**
    for raw_packet in all_raw_packets:
        detected_profile = detect_protocol(raw_packet, protocol_templates)
        profile_name = detected_profile["Protocol_Template"]["Name"]  # Get the profile name
        profile_counts[profile_name] += 1

    # Show the profile counts in the output (dictionary result)
    print("Profile counts:", dict(profile_counts))

    # Select the profile with the highest count (majority)
    majority_profile_name = profile_counts.most_common(1)[0][0]

    # Prepare the final profile using the majority profile template
    majority_profile_template = protocol_templates.get(majority_profile_name, {})
    majority_profile_template["Protocol_Template"]["Name"] = majority_profile_name

    # Save the majority profile and counts to the output file
    save_profile_json(majority_profile_template, args.output_file)  # Save the final profile to the JSON file


if __name__ == "__main__":
    main()
