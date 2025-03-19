# ICS Profile

pip install -e .

1. python parse.py "../Resources/UMAS_pcap_Shade" "modbus"
2. python preprocessor.py "../Data/Packets" "modbus" --columns data func_code
3. Run PREE Heuristic Builder (python ptree.py)
4. python model.py "/Users/masrikdahir/repo/ICSProfile/Data/Train" "persistent"
5. 




### MODBUS
| Field               | Size      | Consistency | Notes                                      |
|-------------------|----------|-------------|--------------------------------------------|
| Transaction ID   | 2 bytes  | ✅ Yes      | Used for request-response tracking        |
| Protocol ID     | 2 bytes  | ✅ Yes      | Always 0000 for Modbus/TCP                 |
| Length          | 2 bytes  | ✅ Yes      | Specifies the byte count after this field  |
| Unit ID         | 1 byte   | ✅ Yes      | Identifies the target device               |
| Function Code   | 1 byte   | ✅ Yes      | Specifies the requested Modbus operation   |
| Payload Data    | Variable | ❌ No       | Depends on the function code and data size |


### DNP3
| Field               | Size      | Consistency | Notes                                      |
|-------------------|----------|-------------|--------------------------------------------|
| Function          | 1 byte   | ✅ Yes      | Defines the operation (e.g., Read, Write) |
| Source           | 2 bytes  | ✅ Yes      | Address of the sender                     |
| Destination      | 2 bytes  | ✅ Yes      | Address of the recipient                  |
| Control          | 1 byte   | ✅ Yes      | Controls sequence number, confirm bits    |
| Application Control | 1 byte | ✅ Yes      | Defines application-layer behavior        |
| Payload Data     | Variable | ❌ No       | Depends on the Function Code              |


### OPCUA
| Field           | Size      | Consistency | Notes                                      |
|---------------|----------|-------------|--------------------------------------------|
| Message Type   | 2 bytes  | ✅ Yes      | Defines the type of message (e.g., HEL, ACK, MSG) |
| Service       | 4 bytes  | ✅ Yes      | Specifies the OPC UA service being requested |
| Request ID    | 4 bytes  | ✅ Yes      | Identifies a unique request               |
| Response Code  | 4 bytes  | ❌ No       | May be missing in some messages           |
| Payload Data  | Variable | ❌ No       | Length depends on the message type        |


### PN_RT
| Field           | Size      | Consistency | Notes                                      |
|---------------|----------|-------------|--------------------------------------------|
| Service Type  | 2 bytes  | ✅ Yes      | Defines the type of Profinet message (e.g., Real-Time (RT), Alarm, or I/O Data) |
| Frame ID      | 4 bytes  | ✅ Yes      | Identifies Profinet frame type            |
| Cycle Counter | 4 bytes  | ✅ Yes      | Incremented for each cyclic Profinet frame |
| Payload Data  | Variable | ❌ No       | Changes based on Service Type and Frame ID |
