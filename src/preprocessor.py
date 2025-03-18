import json
import csv
import argparse
import os


def extract_protocol_data(json_files, protocol, preferred_columns=None):
    """
    Extracts specified protocol data from JSON files and saves it into a CSV file in ../Data/Preprocessed.
    The CSV filename matches the input JSON filename + ".csv".
    """
    extracted_data = []
    all_attributes = set()

    if isinstance(json_files, str):  # If a single file is provided
        json_files = [json_files]

    # First pass to collect all possible attributes
    for json_file in json_files:
        try:
            with open(json_file, 'r') as file:
                data = json.load(file)
                for packet in data:
                    if protocol in packet:
                        protocol_data = packet[protocol]
                        all_attributes.update(protocol_data.keys())
        except Exception as e:
            print(f"Error processing file {json_file}: {e}")

    if preferred_columns is None:
        preferred_columns = sorted(list(all_attributes))  # Use all attributes if not specified

    # Second pass to extract data
    for json_file in json_files:
        try:
            with open(json_file, 'r') as file:
                data = json.load(file)
                for packet in data:
                    if protocol in packet:
                        protocol_data = packet[protocol]
                        values = [protocol_data.get(attr, "") for attr in preferred_columns]  # Fill missing keys
                        extracted_data.append(values)
        except Exception as e:
            print(f"Error processing file {json_file}: {e}")

        # Generate output CSV path
        output_dir = "../Data/Preprocessed"
        os.makedirs(output_dir, exist_ok=True)
        output_csv = os.path.join(output_dir, os.path.basename(json_file).replace(".json", ".csv"))

        if extracted_data:
            with open(output_csv, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(preferred_columns)
                writer.writerows(extracted_data)
            print(f"CSV file '{output_csv}' created successfully.")
        else:
            print(f"No data extracted from {json_file}.")


def main():
    """
    Command-line interface for extracting protocol data from JSON files and saving it into a CSV file.

    This function parses command-line arguments to determine the input JSON path, protocol, output CSV file,
    and optional preferred columns for extraction. It also handles default values in case some arguments
    are missing.

    Args:
        None. All input parameters are taken from the command-line arguments.

    Command-Line Arguments:
        json_path (str): Path to the input JSON file or directory containing JSON files.
        protocol (str): The protocol to extract data for (e.g., "modbus").
        --columns (list, optional): List of column names to include in the CSV (default: all available columns).

    Example:
        python preprocessor.py ../Data/Packets modbus ../Data/Preprocessed/file.csv --columns data func_code

    Notes:
        If no arguments are provided, default values are used:
            - json_path: "../Data/Packets"
            - protocol: "modbus"
            - columns: ["data", "func_code"]

    Returns:
        None. Extracted data is saved to the specified CSV file.
        :rtype: object
    """
    parser = argparse.ArgumentParser(description='Extract protocol data from JSON and save to CSV.')
    parser.add_argument('json_path', nargs='?', default=None, type=str, help='Path to the input JSON file or directory')
    parser.add_argument('protocol', nargs='?', default=None, type=str, help='Protocol to extract (e.g., modbus)')
    parser.add_argument('--columns', type=str, nargs='*', default=None,
                        help='Preferred columns to include in the CSV (default: all available columns)')

    args = parser.parse_args()

    if not args.json_path or not args.protocol:
        args.json_path = "../Data/Packets"
        args.protocol = "modbus"
        args.columns = ["data", "func_code"]
        print("Using default values:")
        print(f"json_path: {args.json_path}")
        print(f"protocol: {args.protocol}")
        print(f"columns: {[str(i) for i in args.columns]}")

    json_path = args.json_path
    filter_protocol = args.protocol
    preferred_columns = args.columns

    if os.path.isdir(json_path):
        json_files = [os.path.join(json_path, f) for f in os.listdir(json_path) if f.endswith('.json')]
    else:
        json_files = [json_path]

    extract_protocol_data(json_files, filter_protocol, preferred_columns)


if __name__ == "__main__":
    main()
