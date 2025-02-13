import json

def load_protocol_template(file_path="profile.json"):
    """
    Loads the protocol template from a JSON file.

    Parameters:
    - file_path (str): Path to the profile.json file.

    Returns:
    - dict: Parsed JSON data containing protocol templates.
    """
    with open(file_path, "r") as f:
        return json.load(f)


def extract_fields(raw_header, protocol_template, depth=0):
    """
    Recursively extracts fields from a protocol template.
    Adds "Payload" field to the last nested level.

    Parameters:
    - raw_header (bytes): The raw protocol data.
    - protocol_template (dict): The protocol template with field offsets.
    - depth (int): Current recursion depth.

    Returns:
    - dict: Extracted fields with nested protocols preserved.
    """
    extracted_data = {}
    last_offset = 0  # Track highest used offset

    for field, offsets in protocol_template.items():
        if field == "Name" or offsets is None:
            continue  # Skip protocol name and null fields

        if isinstance(offsets, list) and len(offsets) == 2:  # Regular field
            start, end = offsets
            if start < len(raw_header):  # Ensure within bounds
                extracted_data[field] = raw_header[start:end].hex()
                last_offset = max(last_offset, end)  # Track highest end offset
        elif isinstance(offsets, dict) and "Protocol_Template" in offsets:  # Nested protocol
            extracted_data[field] = extract_fields(raw_header, offsets["Protocol_Template"], depth + 1)

    # Add "Payload" only to the last nested protocol
    if not any(isinstance(v, dict) for v in extracted_data.values()) and last_offset < len(raw_header):
        extracted_data["Payload"] = raw_header[last_offset:].hex()

    return extracted_data


def generate_protocol_data(raw_header, protocol_template):
    """
    Parses a protocol's raw header and extracts field values based on the JSON template.
    Supports nested protocol extraction.

    Parameters:
    - raw_header (bytes): The raw protocol data.
    - protocol_template (dict): The protocol template with field offsets.

    Returns:
    - dict: A dictionary containing extracted fields from the raw header.
    """
    # Ensure the raw header is a bytes object
    if not isinstance(raw_header, bytes):
        raise TypeError(f"raw_header must be bytes, but got {type(raw_header)}.")

    # Extract protocol name from the template
    protocol_name = protocol_template["Protocol_Template"].get("Name", "Unknown Protocol")

    # Initialize protocol data dictionary
    protocol_data = {
        "Raw": raw_header.hex(),
        "Name": protocol_name,
        "Fields": extract_fields(raw_header, protocol_template["Protocol_Template"])
    }

    return protocol_data


# **🔹 Load Protocol Template**
protocol_templates = load_protocol_template("profile.json")

# **🔹 Example Transport & Raw Data (Hex String Converted to Bytes)**
raw_header = bytes.fromhex("00070000001a015a00fe020a800393543bf093543bf010b2ffff030300140000")

# **🔹 Generate Protocol Data**
data = generate_protocol_data(raw_header, protocol_templates)

# **🔹 Final Output**
result = {
    "Protocol Data": data
}

print(json.dumps(result, indent=4))
