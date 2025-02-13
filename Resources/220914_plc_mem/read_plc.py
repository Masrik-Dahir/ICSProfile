import json
import binascii
import pyshark
import argparse
import time
import csv
from datetime import datetime

# Default Modbus TCP Port
DEFAULT_PORT = 502

def load_protocol_template(file_path):
    """Loads the protocol template from a JSON file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Profile JSON file '{file_path}' not found.")
        exit(1)


def capture_tcp_payload(plc_ip, port, interface="eth0", timeout=10):
    """
    Captures TCP payloads from network traffic for a specific PLC.

    Parameters:
    - plc_ip (str): IP address of the PLC.
    - port (int): Target port to filter packets.
    - interface (str): Network interface to capture packets on.
    - timeout (int): Time (in seconds) to capture packets before stopping.

    Returns:
    - bytes: Extracted TCP payload from the first matching packet.
    """
    try:
        print(f"Listening for TCP packets to {plc_ip}:{port} on {interface} for {timeout} seconds...")

        # Start packet capture with a filter for TCP packets to the PLC
        capture_filter = f"tcp and dst host {plc_ip} and dst port {port}"
        capture = pyshark.LiveCapture(interface=interface, display_filter=capture_filter)

        # Iterate through captured packets
        for packet in capture.sniff_continuously(timeout=timeout):
            if "TCP" in packet and hasattr(packet.tcp, "payload"):
                # Extract and return the payload as bytes
                payload_hex = packet.tcp.payload.replace(":", "")
                payload_bytes = binascii.unhexlify(payload_hex)

                print(f"Captured TCP Payload: {payload_bytes.hex()}")
                return payload_bytes

        print("No matching packets found.")
        return b""

    except Exception as e:
        print(f"Error capturing packets: {e}")
        return b""


def extract_fields(raw_data, protocol_template, depth=0):
    """
    Recursively extracts fields from a protocol template.
    Adds "Payload" field to the last nested level.
    """
    extracted_data = {}
    last_offset = 0  # Track highest used offset

    for field, offsets in protocol_template.items():
        if field == "Name" or offsets is None:
            continue  # Skip protocol name and null fields

        if isinstance(offsets, list) and len(offsets) == 2:  # Regular field
            start, end = offsets
            if start < len(raw_data):  # Ensure within bounds
                extracted_data[field] = raw_data[start:end].hex()
                last_offset = max(last_offset, end)  # Track highest end offset
        elif isinstance(offsets, dict) and "Protocol_Template" in offsets:  # Nested protocol
            extracted_data[field] = extract_fields(raw_data, offsets["Protocol_Template"], depth + 1)

    # Add "Payload" only to the last nested protocol
    if not any(isinstance(v, dict) for v in extracted_data.values()) and last_offset < len(raw_data):
        extracted_data["Payload"] = raw_data[last_offset:].hex()

    return extracted_data


def generate_protocol_data(raw_data, protocol_template):
    """
    Parses a protocol's raw data and extracts field values based on the JSON template.
    Supports nested protocol extraction.
    """
    # Ensure the raw data is a bytes object
    if not isinstance(raw_data, bytes):
        raise TypeError(f"raw_data must be bytes, but got {type(raw_data)}.")

    # Extract protocol name from the template
    protocol_name = protocol_template["Protocol_Template"].get("Name", "Unknown Protocol")

    # Initialize protocol data dictionary
    protocol_data = {
        "Raw": raw_data.hex(),
        "Name": protocol_name,
        "Fields": extract_fields(raw_data, protocol_template["Protocol_Template"])
    }

    return protocol_data


def parse_ip_port(ip_port_str):
    """
    Parses an IP:PORT string and returns the IP and port as separate values.
    If no port is provided, defaults to 502.

    Parameters:
    - ip_port_str (str): IP:PORT string.

    Returns:
    - (str, int): Parsed IP and port.
    """
    parts = ip_port_str.split(":")
    ip = parts[0]
    port = int(parts[1]) if len(parts) > 1 else DEFAULT_PORT
    return ip, port


def main():
    parser = argparse.ArgumentParser(description="PLC Network Traffic Analyzer")

    parser.add_argument("plc_ip", help="IP address and port of the target PLC (format: IP:PORT)")
    parser.add_argument("interface", help="Network interface to capture packets on")
    parser.add_argument("output_file", help="Output file name", nargs='?', default=None)

    parser.add_argument("-r", "--repeat", type=int, default=0, help="Repeat every N seconds")
    parser.add_argument("-c", "--csv", help="CSV file containing memory areas to read", nargs='?')
    parser.add_argument("-p", "--profile", help="Path to the profile JSON file", default="profile.json")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Packet capture timeout (seconds)")

    args = parser.parse_args()

    # Parse PLC IP and Port from the argument
    plc_ip, port = parse_ip_port(args.plc_ip)

    global_counter = 0

    while True:  # Infinite loop until user stops or repeat is not specified
        start_time = time.time()

        # Capture data from the network
        tcp_payload = capture_tcp_payload(plc_ip, port, args.interface, args.timeout)

        if not tcp_payload:
            print("No data captured from PLC.")
            continue

        # Load protocol template from the provided profile path
        protocol_templates = load_protocol_template(args.profile)

        # Generate protocol data
        data = generate_protocol_data(tcp_payload, protocol_templates)

        # Print output
        result = {"Protocol Data": data}
        print(json.dumps(result, indent=4))

        # Save output if specified
        if args.output_file:
            file_name = f"{args.output_file}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            with open(file_name, "w") as f:
                json.dump(result, f, indent=4)
            print(f"File saved: {file_name}")

        print(f"{time.time() - start_time} seconds to analyze network traffic.")

        if args.repeat <= 0:
            break  # Stop looping if repeat is not set

        print(f"Waiting {args.repeat} seconds before repeating...")
        time.sleep(args.repeat)
        global_counter += 1


if __name__ == '__main__':
    main()
