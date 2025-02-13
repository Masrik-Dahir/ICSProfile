import sys, os
import struct
import binascii
import socket
import argparse
import time
from random import randint
import time
import csv
from datetime import datetime

# Configuration
CSV_CREATE_FILE = False

# M221 message (modbus payload after the function code) offset in TCP payload
M221_OFFSET = 8 
MODBUS_PORT = 502

M221_MAX_PAYLOAD_SIZE = 236
# Minimum size of m221 control logic which contains both input and ouput
MIN_CONTROL_LOGIC = 6

# Padding size can be configurable according to attacker's control logic
# 230 = M221_MAX_PAYLOAD_SIZE - MIN_CONTROL_LOGIC
FRONT_PADDING_SIZE = 230

# 235 = M221_MAX_PAYLOAD_SIZE - 1 (transfer one byte at a time)
BACK_PADDING_SIZE = 235

class M221_cl_injector():
    def __init__(self, targetIP):
        self.tranID = 1
        self.proto = '\x00\x00'
        self.len = 0
        self.unitID = '\x01'
        # Function code: Unity (Schneider) (90)
        self.fnc = '\x5a'

        self.m221_sid = '\x00'

        self.send_counter = 0

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((targetIP, MODBUS_PORT))

        self.set_m221_session_id()

        # (start addr, end addr, type) of each block
        self.conf1_info = ()
        self.conf2_info = ()
        self.code_info = ()
        self.data1_info = ()
        self.data2_info = ()
        self.zip_info = ()

    def send_recv_msg(self, modbus_data):
        self.send_counter += 1
        print("#", self.send_counter, "#")

        self.len = len(modbus_data) + len(self.unitID) + len(self.fnc)  
        tcp_payload = struct.pack(">H", self.tranID) + self.proto + struct.pack(">H", self.len) + self.unitID + self.fnc + modbus_data
        self.tranID = (self.tranID + 1) % 65536

        self.sock.send(tcp_payload)
        
        s = binascii.hexlify(tcp_payload)
        t = iter(s)
        print("--> " + ':'.join(a+b for a,b in zip(t,t)) + " (" + str(len(tcp_payload)) + ")")

        recv_buf = self.sock.recv(1000)
        r = binascii.hexlify(recv_buf)
        t = iter(r)
        print("<-- " + ':'.join(a+b for a,b in zip(t,t)) + " (" + str(len(recv_buf)) + ")")

        return recv_buf

    def close_socket(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def close_connection(self):
        modbus_data = self.m221_sid + '\x11'
        self.send_recv_msg(modbus_data)
        self.close_socket()

    def set_m221_session_id(self):
        sid_req_payload = '\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.m221_sid = self.send_recv_msg(sid_req_payload)[-1]
        print("m221 session id: " + binascii.hexlify(self.m221_sid))

    """
    def write_program(self):
        modbus_data = self.m221_sid + '\x29' + '\xb0\xe0\x01\x07\x06\x00\x7c\x2c\xfd\xe0\x2d\x02'

        self.send_recv_msg(modbus_data)
    """

    # Send read requests to PLC to get a file
    def read_file(self, file_addr, file_type, file_size):
        max_data_unit = 236
        remained = file_size
        file_buf = ''
        
        while (remained > 0):
            if remained >= max_data_unit:
                fragment_size = max_data_unit
            else:
                fragment_size = remained
            # read request: 0x28
            modbus_data = '\x00\x28' + struct.pack("<H", file_addr) + file_type + struct.pack("<H", fragment_size)
            file_buf += self.send_recv_msg(modbus_data)[M221_OFFSET+4:] # 0x00fe + response data size (2 bytes)
            remained -= fragment_size
            file_addr += fragment_size
        return file_buf        

    def read_mem(self, start_addr, size):
        max_data_unit = 236 #F6 #236
        addr = start_addr
        remained = size
        file_buf = ''
        
        while (remained > 0):
            if remained >= max_data_unit:
                fragment_size = max_data_unit
            else:
                fragment_size = remained
            # read request: 0x28
            modbus_data = '\x00\x28' + struct.pack("<I", addr) + struct.pack("<H", fragment_size)
            file_buf += self.send_recv_msg(modbus_data)[M221_OFFSET+4:] # 0x00fe + response data size (2 bytes)
            remained -= fragment_size
            addr += fragment_size
        return file_buf        
        
def beautify_size(size):
    res_s = size

    if size/1024**2 >= 1:
        res_s = str(size/1024**2)+" Mbytes"
    elif size/1024 >= 1:
        res_s = str(size/1024)+" Kbytes"
    else:
        res_s = str(size)+" bytes"

#    elif size/1024**3 > 0:
#        res_s = str(size/1024**3)+" Gbytes"

    return res_s

def gen_filename(file_name, count):
    base_name, extension = os.path.splitext(file_name)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return "{0}_{1}{2}".format(base_name, timestamp, extension) # Append the timestamp to the file name

    #base_name, extension = os.path.splitext(file_name)
    #return "{0}_{1:04X}{2}".format(base_name, count, extension) # Append the four hex digits to the file name

def main():
    parser = argparse.ArgumentParser(description="M221 Control Logic Injector")

    parser.add_argument("plc_ip", help="IP address of the target PLC")

    parser.add_argument("start_addr", help="Start memory address (in hex)",nargs='?', default=None)
    parser.add_argument("size", help="Byte size to read", nargs='?', default=None)
    parser.add_argument("output_file", help="Output file name",nargs='?', default=None)

    parser.add_argument("-r", "--repeat", type=int, default=0, help="Repeat every N seconds")
    parser.add_argument("-c", "--csv", help="CSV file containing memory areas to read", nargs='?')

    args = parser.parse_args()

    isFromCSV = False

    if args.csv is not None:
        # CSV mode
        with open(args.csv, 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            next(csvreader)  # Skip the first row (header)
            mem_areas = list(csvreader)
            isFromCSV = True
    else:
        # Regular mode
        mem_areas = [(args.output_file, args.start_addr, args.size, 1)] #Repeat count will be remain as 1

    global_counter = 0
    file_count = 0

    while True:  # This loop will repeat until the program is manually terminated
        for area in mem_areas:
            area_name, start_addr_hex, size_hex, repeat_count = area
            start_addr = int(start_addr_hex, 16)
            size = int(size_hex, 16)
            repeat_count = int(repeat_count)
            
            if global_counter % repeat_count != 0:
                continue

            start_time = time.time()
            m221_injector = M221_cl_injector(args.plc_ip)

            mem_block = m221_injector.read_mem(start_addr, size)
            m221_injector.close_connection()

            #File Creation Part begins
            if isFromCSV and not CSV_CREATE_FILE:
                continue

            file_name = gen_filename(area_name, file_count)
            print("File [",file_name,"] is created.")
            with open(file_name, "w") as f:
                f.write(mem_block)
            file_count += 1

            print("{0} seconds to read : {1}".format(time.time() - start_time, beautify_size(size)))

        if args.repeat <= 0:
            break  # If repeat is not specified or is 0, terminate the loop after the first iteration

        print("Waiting for {0} seconds before repeating".format(args.repeat))
        time.sleep(args.repeat)  # Pause for the specified number of seconds
        global_counter += 1

if __name__ == '__main__':
    main()
