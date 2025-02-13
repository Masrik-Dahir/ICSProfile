import binascii
import json

def detect_protocol(transport_header: str, protocol_templates: dict) -> dict:
    """
    Detects the transport protocol and generates a JSON profile in the required format.
    Checks if UMAS exists within the Modbus payload.

    Parameters:
    - transport_header (str): Hexadecimal string representing the transport header.
    - protocol_templates (dict): Dictionary containing protocol field structures.

    Returns:
    - dict: JSON structure with detected protocol fields in the required format.
    """

    # Convert transport header from hex string to bytes
    transport_header = binascii.unhexlify(transport_header)

    if len(transport_header) < 2:
        return {"Protocol_Template": {"Name": "Unknown"}}  # Not enough data to analyze

    raw_packet = transport_header

    # Iterate over protocols to detect a match
    for protocol_name, template in protocol_templates.items():
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
                "Name": protocol_name
            }
        }

        for field, offsets in field_offsets.items():
            profile["Protocol_Template"][field] = offsets  # Keep original offsets from template

        # Special handling for Modbus to check for UMAS nesting
        if protocol_name == "Modbus" and raw_packet[7] == 0x5A:
            umas_template = protocol_templates.get("UMAS", {}).get("Protocol_Template", {})
            umas_payload_start = 8  # Start of UMAS inside Modbus payload

            # Extract only the **end** index properly while avoiding NoneType
            umas_max_offset = max(
                [umas_payload_start + offsets[1] for offsets in umas_template.values() if isinstance(offsets, list) and len(offsets) == 2],
                default=0
            )

            if len(raw_packet) >= umas_max_offset:
                # Fix: Construct UMAS profile as a separate dictionary **before** assigning
                umas_profile = {"Name": "UMAS"}  # Ensure Name is explicitly set
                for field, offsets in umas_template.items():
                    if isinstance(offsets, list) and len(offsets) == 2:
                        umas_profile[field] = [umas_payload_start + offsets[0], umas_payload_start + offsets[1]]
                    else:
                        umas_profile[field] = None

                # Fix: Assign `Nested_Protocol` correctly
                profile["Protocol_Template"]["Nested_Protocol"] = umas_profile

        return profile  # Return first matching protocol

    return {"Protocol_Template": {"Name": "Other"}}  # No match found


def save_profile_json(data, filename="profile.json"):
    """
    Saves the protocol profile in the required format to a JSON file.

    Parameters:
    - data (dict): The protocol profile data.
    - filename (str): The output JSON file name.
    """
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Profile saved to {filename}")


# **🔹 Updated Protocol Templates (UMAS Payload Removed)**
protocol_templates = {
    "Modbus": {
        "Protocol_Template": {
            "Name": "Modbus",
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
    "UMAS": {
        "Protocol_Template": {
            "Name": "UMAS",
            "Header": [0, 2],
            "Subfunction": [2, 4],
            "Session_ID": [4, 6],
            "Device_ID": [6, 10],
            "Request_ID": [10, 14],
            "Command_Code": [14, 16],
            "Status": [16, 18]
        }
    }
}

# **🔹 Test the function**
transport_header = "00070000001a015a00fe020a800393543bf093543bf010b2ffff030300140000"

detected_profile = detect_protocol(transport_header, protocol_templates)

# **🔹 Save to profile.json**
save_profile_json(detected_profile)
