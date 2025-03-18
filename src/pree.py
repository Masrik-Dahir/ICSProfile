import pandas as pd
import os


def extract_target_code(hex_data):
    """Extracts target function code from the data field, handles non-string inputs safely."""
    if isinstance(hex_data, str):  # Ensure the input is a string
        return hex_data.split(":")[1] if ":" in hex_data else None
    return None  # Return None for non-strings


def extract_target_payload(hex_data):
    """Extracts target payload from the data field, handles non-string inputs safely."""
    if isinstance(hex_data, str):  # Ensure the input is a string
        return ":".join(hex_data.split(":")[2:]) if ":" in hex_data else None
    return None  # Return None for non-strings


def extract_target_transaction_id(hex_data):
    """Extracts target transaction ID from the data field, handles non-string inputs safely."""
    if isinstance(hex_data, str):  # Ensure the input is a string
        return hex_data.split(":")[0] if ":" in hex_data else None
    return None  # Return None for non-strings


def process_umas_data(input_path, output_dir):
    """Processes a CSV file or all CSV files in a directory, extracts target protocol fields, and saves enhanced data."""

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Create a list of files to process
    if os.path.isdir(input_path):
        files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith(".csv")]
    else:
        files = [input_path]

    for file in files:
        if not os.path.exists(file):
            print(f"File not found: {file}")
            continue

        # Read the input CSV file
        df = pd.read_csv(file)

        # Dynamically add 'parent_' prefix to all existing columns
        df = df.rename(columns={col: f"parent_{col}" for col in df.columns})

        if "parent_data" not in df:
            print(f"'data' column not found in the file: {file}")
            continue

        # Applying extraction functions to create new columns
        df["target_code"] = df["parent_data"].apply(extract_target_code)
        df["target_payload"] = df["parent_data"].apply(extract_target_payload)
        df["target_transaction_id"] = df["parent_data"].apply(extract_target_transaction_id)

        # Construct output file path
        output_file_path = os.path.join(output_dir, os.path.basename(file))

        # Save the updated DataFrame to the output CSV file
        df.to_csv(output_file_path, index=False)
        print(f"Processed data saved to: {output_file_path}")


# Example usage
input_path = "../Data/Preprocessed/"  # Can be a file or a directory
output_dir = "../Data/Train/"
process_umas_data(input_path, output_dir)
