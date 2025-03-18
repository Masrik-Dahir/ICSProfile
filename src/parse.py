import os
import json
import sys
import pyshark


def extract_protocols_from_pcap(pcap_path, filter_protocol=None):
    capture = pyshark.FileCapture(pcap_path)
    extracted_data = []

    for packet in capture:
        packet_data = {}
        include_packet = False

        for layer in packet.layers:
            layer_name = layer.layer_name

            if layer_name not in packet_data:
                packet_data[layer_name] = {}

            for field in layer.field_names:
                try:
                    packet_data[layer_name][field] = getattr(layer, field)
                except AttributeError:
                    packet_data[layer_name][field] = None

            if filter_protocol and filter_protocol.lower() in layer_name.lower():
                include_packet = True

        if not filter_protocol or include_packet:
            extracted_data.append(packet_data)

    capture.close()
    return extracted_data


def save_protocols_to_json(pcap_path, output_dir, filter_protocol=None):
    protocols_data = extract_protocols_from_pcap(pcap_path, filter_protocol)
    json_filename = os.path.join(output_dir, os.path.basename(pcap_path) + ".json")

    with open(json_filename, 'w') as json_file:
        json.dump(protocols_data, json_file, indent=4)

    print(f"Extracted protocols saved to {json_filename}")


if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python extract_protocols.py <pcapng_directory> [filter_protocol]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    filter_protocol = sys.argv[2] if len(sys.argv) == 3 else None

    if not os.path.exists(pcap_path):
        print("Error: Specified file does not exist.")
        sys.exit(1)

    output_dir = os.path.dirname(pcap_path)
    save_protocols_to_json(pcap_path, output_dir, filter_protocol)
