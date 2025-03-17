import json

def parse_modbus_umas_from_wireshark_json(json_file_path, output_file_path):
    """
    Parses Modbus+UMAS data from Wireshark JSON.
    Outputs CSV with columns:
      1) ModbusFunctionCode   (0xNN)
      2) UMASFunctionCode     (0xNNNN)
      3) UMASPayload          (0xAA00BB..., uppercase hex, prefixed with '0x' if non-empty)
      4) ModbusData           (the original modbus.data string from JSON, which may be colon-delimited hex)

    Note: Removed TransactionID and ProtocolID from the output.
    """

    with open(json_file_path, "r", encoding="utf-8") as f:
        packets = json.load(f)

    with open(output_file_path, 'w', encoding="utf-8") as f_out:
        # Write CSV header (4 columns now)
        f_out.write("ModbusData,ModbusFunctionCode,UMASFunctionCode,UMASPayload\n")

        count_parsed = 0

        for i, pkt in enumerate(packets):
            # Adapt if your JSON structure is nested under _source/layers, etc.
            mbtcp  = pkt.get("mbtcp", {})
            modbus = pkt.get("modbus", {})

            if not mbtcp or not modbus:
                continue

            # Modbus function code from "modbus.func_code" (typically a hex string like "90")
            modbus_func_str = modbus.get("func_code", "")
            if not modbus_func_str:
                continue

            # Convert that to an int, then format as "0xNN"
            try:
                modbus_func_int = int(modbus_func_str, 16)
                modbus_func_hex = f"0x{modbus_func_int:02X}"  # e.g., "0x5A"
            except ValueError:
                # If it fails to parse, skip
                continue

            # The raw modbus data (colon-delimited hex)
            modbus_data_hex = modbus.get("data", "")
            if not modbus_data_hex:
                continue

            # Convert to bytes for UMAS offset parsing
            modbus_data = bytes.fromhex(modbus_data_hex.replace(":", ""))

            # UMAS function code at [14:16] (adjust if needed)
            if len(modbus_data) < 16:
                continue
            umas_func_code_bytes = modbus_data[14:16]
            umas_func_int = int.from_bytes(umas_func_code_bytes, byteorder="big")
            umas_func_hex = f"0x{umas_func_int:04X}"

            # UMAS payload at [18:] (adjust if needed)
            if len(modbus_data) > 18:
                umas_payload = modbus_data[18:]
            else:
                umas_payload = b""

            # Convert UMAS payload to uppercase hex, with "0x" if non-empty
            umas_payload_str = umas_payload.hex().upper()
            if umas_payload_str:
                umas_payload_str = f"0x{umas_payload_str}"

            # Write our 4-column CSV
            line = (
                f"{modbus_data_hex},"
                f"{modbus_func_hex},"
                f"{umas_func_hex},"
                f"{umas_payload_str}\n"
            )
            f_out.write(line)
            count_parsed += 1

        print(f"Done. Parsed {count_parsed} packets. Output saved to {output_file_path}")


if __name__ == "__main__":
    # Example usage
    input_json = r"F:\Repo\ICSProfile\Resources\UMAS_pcap_Shade\CaptureTrafficWithTimer.pcapng.json"
    output_txt = "modbus_umas_data.txt"
    parse_modbus_umas_from_wireshark_json(input_json, output_txt)
