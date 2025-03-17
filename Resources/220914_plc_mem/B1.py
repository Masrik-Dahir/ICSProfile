from scapy.all import rdpcap, ModbusADU

# Path to the pcapng file
file_path = '/mnt/data/CaptureTrafficWithTimer.pcapng'

# Function to parse Modbus-Umas packets using Scapy
def parse_modbus_umas_packets_scapy(file_path):
    packets = rdpcap(file_path)
    formatted_packets = []

    for packet in packets:
        if packet.haslayer(ModbusADU):
            try:
                # Raw data
                raw_data = str(packet[ModbusADU].payload)

                # Fields
                transaction_id = packet[ModbusADU].transId
                protocol_id = packet[ModbusADU].protoId
                length = packet[ModbusADU].len
                unit_id = packet[ModbusADU].unitId

                # Modbus function code and further parsing might be needed based on the payload structure
                function_code = packet[ModbusADU].funcCode

                # Assume UMAS specific fields are within the payload and this is just an example to fit the data provided
                if len(raw_data) >= 36:  # Ensure there's enough data to extract hypothetical UMAS fields
                    umas_header = raw_data[:4]
                    umas_subfunction = raw_data[4:8]
                    umas_session_id = raw_data[8:12]
                    umas_device_id = raw_data[12:20]
                    umas_request_id = raw_data[20:28]
                    umas_command_code = raw_data[28:32]
                    umas_status = raw_data[32:36]
                    umas_payload = raw_data[36:]

                    # Formatted packet
                    formatted_packet = {
                        "Protocol Data": {
                            "Raw": raw_data.encode().hex(),
                            "Name": "Modbus-Umas",
                            "Fields": {
                                "Transaction_ID": transaction_id,
                                "Protocol_ID": protocol_id,
                                "Length": length,
                                "Unit_ID": unit_id,
                                "Function_Code": function_code,
                                "UMAS": {
                                    "Header": umas_header,
                                    "Subfunction": umas_subfunction,
                                    "Session_ID": umas_session_id,
                                    "Device_ID": umas_device_id,
                                    "Request_ID": umas_request_id,
                                    "Command_Code": umas_command_code,
                                    "Status": umas_status,
                                    "Payload": umas_payload
                                }
                            }
                        }
                    }
                    formatted_packets.append(formatted_packet)
            except AttributeError:
                # In case some attributes are missing from the packet
                continue

    return formatted_packets

# Parse packets using Scapy
parsed_packets_scapy = parse_modbus_umas_packets_scapy(file_path)
print(parsed_packets_scapy[:3])  # Show only the first 3 packets for brevity
