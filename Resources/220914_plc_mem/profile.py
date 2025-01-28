import sys
import os
import struct
import binascii
import socket
import argparse
import time
import csv
from datetime import datetime

# Configuration
CSV_CREATE_FILE = False

# M221 message (modbus payload after the function code) offset in TCP payload
M221_OFFSET = 8
MODBUS_PORT = 502

M221_MAX_PAYLOAD_SIZE = 236
MIN_CONTROL_LOGIC = 6
FRONT_PADDING_SIZE = 230
BACK_PADDING_SIZE = 235


class M221_cl_injector():
    def __init__(self, targetIP):
        self.tranID = 1
        self.proto = '\x00\x00'
        self.len = 0
        self.unitID = '\x01'
        self.fnc = '\x5a'
        self.m221_sid = '\x00'
        self.send_counter = 0

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((targetIP, MODBUS_PORT))

        self.set_m221_session_id()

    def send_recv_msg(self, modbus_data):
        self.send_counter += 1
        print("#", self.send_counter, "#")

        self.len = len(modbus_data) + len(self.unitID) + len(self.fnc)
        tcp_payload = struct.pack(">H", self.tranID) + self.proto + struct.pack(">H",
                                                                                self.len) + self.unitID + self.fnc + modbus_data
        self.tranID = (self.tranID + 1) % 65536

        self.sock.send(tcp_payload)
        recv_buf = self.sock.recv(1000)
        return recv_buf

    def close_socket(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def close_connection(self):
        modbus_data = self.m221_sid + '\x11'
        self.send_recv_msg(modbus_data)
        self.close_socket()

    def set_m221_session_id(self):
        sid_req_payload = '\x00' * 40
        self.m221_sid = self.send_recv_msg(sid_req_payload)[-1]
        print("m221 session id:", binascii.hexlify(self.m221_sid))

    def read_mem(self, start_addr, size):
        max_data_unit = 236
        addr = start_addr
        remained = size
        file_buf = ''

        while remained > 0:
            fragment_size = min(remained, max_data_unit)
            modbus_data = '\x00\x28' + struct.pack("<I", addr) + struct.pack("<H", fragment_size)
            file_buf += self.send_recv_msg(modbus_data)[M221_OFFSET + 4:]
            remained -= fragment_size
            addr += fragment_size
        return file_buf


def beautify_size(size):
    if size >= 1024 ** 2:
        return f"{size / 1024 ** 2:.2f} Mbytes"
    elif size >= 1024:
        return f"{size / 1024:.2f} Kbytes"
    else:
        return f"{size} bytes"


def gen_filename(file_name, count):
    base_name, extension = os.path.splitext(file_name)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return f"{base_name}_{timestamp}{extension}"


def create_profile(plc_ip):
    print(f"Creating profile for PLC at {plc_ip}...")
    injector = M221_cl_injector(plc_ip)
    injector.close_connection()
    print("Profile created.")


def read_from_profile(plc_ip, start_addr, size, output_file):
    injector = M221_cl_injector(plc_ip)
    mem_block = injector.read_mem(start_addr, size)
    injector.close_connection()

    file_name = gen_filename(output_file, 0)
    with open(file_name, "w") as f:
        f.write(mem_block)
    print(f"Memory content written to {file_name}")


def main():
    parser = argparse.ArgumentParser(description="M221 Control Logic Profile and Reader")

    parser.add_argument("plc_ip", help="IP address of the target PLC")
    parser.add_argument("--create-profile", action="store_true", help="Create a profile for the PLC")
    parser.add_argument("--read", action="store_true", help="Read memory from PLC using profile")
    parser.add_argument("--start-addr", type=lambda x: int(x, 16), help="Start memory address (in hex)", default=0)
    parser.add_argument("--size", type=lambda x: int(x, 16), help="Byte size to read", default=0)
    parser.add_argument("--output-file", help="Output file name", default="output.bin")

    args = parser.parse_args()

    if args.create_profile:
        create_profile(args.plc_ip)

    if args.read:
        read_from_profile(args.plc_ip, args.start_addr, args.size, args.output_file)


if __name__ == "__main__":
    main()


# usage: profile.py[-h][--create - profile][--read][--start - addr
# START_ADDR]
# [--size SIZE][--output - file
# OUTPUT_FILE]
# plc_ip

