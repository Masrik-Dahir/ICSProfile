import sys
import os
import json
import pyshark
import binascii
import socket
import struct
from datetime import datetime


class ModbusMemoryReader:
    def __init__(self, target_ip):
        self.tran_id = 1
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((target_ip, 502))
        self.memory_data = {}
        self.set_m221_session_id()

    def send_recv_msg(self, modbus_data):
        self.tran_id = (self.tran_id + 1) % 65536
        length = len(modbus_data) + 2  # Unit ID + Function Code
        tcp_payload = struct.pack(">H", self.tran_id) + b"\x00\x00" + struct.pack(">H",
                                                                                  length) + b"\x01\x5a" + modbus_data
        self.sock.send(tcp_payload)
        recv_buf = self.sock.recv(1024)
        return tcp_payload, recv_buf

    def set_m221_session_id(self):
        sid_req_payload = b'\x00\x10' + b'\x00' * 36
        _, response = self.send_recv_msg(sid_req_payload)
        self.session_id = response[-1]

    def store_memory(self, start_addr, data):
        self.memory_data[start_addr] = binascii.hexlify(data).decode()

    def read_memory(self, start_addr, size):
        max_unit_size = 236
        addr = start_addr
        remained = size
        data_buffer = b""

        while remained > 0:
            fragment_size = min(remained, max_unit_size)
            modbus_data = b'\x00\x28' + struct.pack("<I", addr) + struct.pack("<H", fragment_size)
            tcp_payload, response = self.send_recv_msg(modbus_data)
            data_buffer += response[8 + 4:]
            remained -= fragment_size
            addr += fragment_size

            print(f"Sent TCP Payload: {binascii.hexlify(tcp_payload).decode()}")
            print(f"Received Response: {binascii.hexlify(response).decode()}")

        return data_buffer

    def close_connection(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def get_memory_data(self):
        return self.memory_data


def extract_packet_data(pcap_file, protocol):
    packets_info = []
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    for packet in cap:
        packet_data = {}
        packet_data["Timestamp"] = str(packet.sniff_time)
        raw_packet = binascii.hexlify(bytes.fromhex(packet.frame_raw.value)).decode() if hasattr(packet,
                                                                                                 'frame_raw') else ""

        # Extracting Ethernet header (14 bytes)
        ethernet_header = raw_packet[:28]

        # Extracting IPv4 header dynamically
        ipv4_header_length = (int(raw_packet[29], 16) & 0x0F) * 4  # Extract IHL field
        ipv4_header_end = 28 + (ipv4_header_length * 2)
        ipv4_header = raw_packet[28:ipv4_header_end]

        # Check if protocol is TCP or UDP
        transport_protocol = raw_packet[46:48]  # Extract protocol field from IP header
        is_tcp = transport_protocol == "06"  # TCP protocol number
        is_udp = transport_protocol == "11"  # UDP protocol number

        transport_header = ""
        transport_header_end = ipv4_header_end
        if is_tcp:
            transport_header_length = (int(raw_packet[ipv4_header_end + 24:ipv4_header_end + 26], 16) >> 4) * 4
            transport_header_end += (transport_header_length * 2)
            transport_header = raw_packet[ipv4_header_end:transport_header_end]
        elif is_udp:
            transport_header_end += 16 * 2  # UDP header is always 8 bytes (16 hex characters)
            transport_header = raw_packet[ipv4_header_end:transport_header_end]

        # Extracting protocol-specific data
        protocol_data = {}
        if protocol.lower() == "modbus" and hasattr(packet, 'modbus'):
            modbus_tcp_header = raw_packet[transport_header_end:]
            modbus_length = int(modbus_tcp_header[8:12], 16) * 2  # Convert length field to bytes
            protocol_data["Modbus"] = {
                "Raw": modbus_tcp_header,
                "Transaction_ID": modbus_tcp_header[:4],
                "Protocol_ID": modbus_tcp_header[4:8],
                "Length": modbus_tcp_header[8:12],
                "Unit_ID": modbus_tcp_header[12:14],
                "Function_Code": modbus_tcp_header[14:16],
                "Payload_Data": modbus_tcp_header[16:16 + modbus_length - 2]
            }
        elif protocol.lower() == "dnp3" and hasattr(packet, 'dnp3'):
            dnp3_header = raw_packet[transport_header_end:]
            dnp3_length = len(dnp3_header)
            header_size = 14
            payload_data = dnp3_header[header_size:] if dnp3_length > header_size else ""
            protocol_data["DNP3"] = {
                "Raw": dnp3_header,
                "Function": dnp3_header[:2],
                "Source": dnp3_header[2:6],
                "Destination": dnp3_header[6:10],
                "Control": dnp3_header[10:12],
                "Application_Control": dnp3_header[12:14],
                "Payload_Data": payload_data
            }
        elif protocol.lower() == "opc" and hasattr(packet, 'opcua'):
            opc_header = raw_packet[transport_header_end:]
            opc_length = len(opc_header)
            header_size = 14
            payload_data = opc_header[header_size:] if opc_length > header_size else ""
            protocol_data["OPC"] = {
                "Raw": opc_header,
                "Message_Type": opc_header[:2],
                "Service": opc_header[2:6],
                "Request_ID": opc_header[6:10],
                "Response_Code": opc_header[10:14] if opc_length >= 14 else "",
                "Payload_Data": payload_data
            }
        elif protocol.lower() == "profinet" and hasattr(packet, 'pn_rt'):
            profinet_header = raw_packet[transport_header_end:]
            profinet_length = len(profinet_header)
            header_size = 10
            payload_data = profinet_header[header_size:] if profinet_length > header_size else ""
            protocol_data["Profinet"] = {
                "Raw": profinet_header,
                "Service_Type": profinet_header[:2],
                "Frame_ID": profinet_header[2:6],
                "Cycle_Counter": profinet_header[6:10],
                "Payload_Data": payload_data
            }

        if protocol_data:
            packet_data.update(
                {"Ethernet": ethernet_header, "IPv4 Header": ipv4_header, "Transport Header": transport_header,
                 **protocol_data})
            packets_info.append(packet_data)

    cap.close()
    return packets_info


def process_pcap_directory(pcap_dir, output_file, protocol):
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcapng')]
    all_packets = []

    for pcap_file in pcap_files:
        file_path = os.path.join(pcap_dir, pcap_file)
        print(f"Processing {file_path} for {protocol}...")
        packets = extract_packet_data(file_path, protocol)
        all_packets.extend(packets)

    output = {"Packets": all_packets}

    with open(output_file, "w") as f:
        json.dump(output, f, indent=4)
    print(f"Packet data exported to {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PCAP Packet Extractor")
    parser.add_argument("--pcap-dir", help="Directory containing PCAPNG files", required=True)
    parser.add_argument("--output-file", help="Output file name for extracted packet data", default="packet_data.json")
    parser.add_argument("--protocol", help="Specify protocol", choices=["Modbus", "DNP3", "OPC", "Profinet"],
                        required=True)
    args = parser.parse_args()

    process_pcap_directory(args.pcap_dir, args.output_file, args.protocol)


if __name__ == "__main__":
    main()
