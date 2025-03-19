import os
import json
import sys
import pyshark
import argparse

from util import get_parent_directory


def extract_protocols_from_pcap(pcap_path, filter_protocol=None):
    """
    Extracts protocols from a PCAP file and optionally filters by a specific protocol.

    Args:
        pcap_path (str): Path to the PCAP file.
        filter_protocol (str, optional): Name of the protocol to filter results. Defaults to None.

    Returns:
        list: A list of dictionaries containing protocol-layer data from each packet in the PCAP file.
        :param pcap_path: 
        :param filter_protocol: 
        :return: 
    """
    # Open the PCAP file for reading using pyshark
    capture = pyshark.FileCapture(pcap_path)
    extracted_data = []

    for packet in capture:
        packet_data = {}
        include_packet = False

        # Parse each layer in the packet
        for layer in packet.layers:
            layer_name = layer.layer_name  # Name of the protocol layer (e.g. 'ip', 'tcp')

            # Initialize dictionary for the layer if not already present
            if layer_name not in packet_data:
                packet_data[layer_name] = {}

            # Extract all fields within the protocol layer
            for field in layer.field_names:
                try:
                    packet_data[layer_name][field] = getattr(layer, field)
                except AttributeError:
                    # Handle missing fields gracefully
                    packet_data[layer_name][field] = None

            # Check if the current protocol layer matches the filter
            if filter_protocol and filter_protocol.lower() in layer_name.lower():
                include_packet = True

        # Add the packet to the output if no filter is applied, or if the filter matches
        if not filter_protocol or include_packet:
            extracted_data.append(packet_data)

    # Close the capture file to release resources
    capture.close()
    return extracted_data


def save_protocols_to_json(pcap_path, output_dir, filter_protocol=None):
    """
    Extracts protocols from a PCAP file and saves the extracted data to a JSON file.

    Args:
        pcap_path (str): Path to the PCAP file.
        output_dir (str): Directory where the JSON file will be saved.
        filter_protocol (str, optional): Name of the protocol to filter results. Defaults to None.

    Returns:
        None
        :param pcap_path: 
        :param output_dir: 
        :param filter_protocol: 
    """
    # Extract protocol data from the given PCAP file
    protocols_data = extract_protocols_from_pcap(pcap_path, filter_protocol)

    # Get the directory of the running script
    project_path = os.path.dirname(os.path.abspath(__file__))
    parent = get_parent_directory(project_path)

    # Construct a path for the output JSON file
    json_filename = os.path.join(parent, "Data", "Packets", os.path.basename(pcap_path) + ".json")

    # Save the extracted data to the JSON file
    with open(json_filename, 'w') as json_file:
        json.dump(protocols_data, json_file, indent=4)

    # Print a success message with the location of the saved file
    print(f"Extracted protocols saved to {json_filename}")


def process_pcap_directory(directory_path, filter_protocol=None):
    """
    Processes all PCAP files in a directory and extracts protocols from each.

    Args:
        directory_path (str): Path to the directory containing PCAP files.
        filter_protocol (str, optional): Name of the protocol to filter results. Defaults to None.

    Returns:
        None
        :param directory_path: 
        :param filter_protocol: 
    """
    # Validate if the given path is a directory
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.")
        sys.exit(1)

    # Iterate over all files in the directory
    for file in os.listdir(directory_path):
        # Process files with extensions .pcapng or .pcap only
        if file.endswith(".pcapng") or file.endswith(".pcap"):
            file_path = os.path.join(directory_path, file)
            save_protocols_to_json(file_path, directory_path, filter_protocol)


def main():
    """
    Main function, entry point of the script.
    Parses command-line arguments and extracts protocols from PCAP files or directories.

    Args:
        None

    Returns:
        None
        :rtype: object
    """
    # Define command-line arguments
    parser = argparse.ArgumentParser(description="Extract protocols from PCAP files and save to JSON.")
    parser.add_argument("pcap_path", nargs="?", default=None,
                        help="Path to a PCAP file or directory containing PCAP files.")
    parser.add_argument("-f", "--filter", help="Filter by a specific protocol.", default=None)

    args = parser.parse_args()

    # Apply default values if no arguments are provided
    if not args.pcap_path:
        pcap_path = "../Resources/UMAS_pcap_Shade"
        filter_protocol = "modbus"
        print(f"No arguments provided. Using default values: "
              f"pcap_path={pcap_path}, "
              f"filter_protocol={filter_protocol}")
    else:
        pcap_path = args.pcap_path
        filter_protocol = args.filter

    # Validate if the given path exists
    if not os.path.exists(pcap_path):
        print("Error: Specified file or directory does not exist.")
        sys.exit(1)

    # Determine if the path is a directory or a single file
    if os.path.isdir(pcap_path):
        process_pcap_directory(pcap_path, filter_protocol)
    else:
        output_dir = os.path.dirname(pcap_path)
        save_protocols_to_json(pcap_path, output_dir, filter_protocol)


if __name__ == "__main__":
    main()
