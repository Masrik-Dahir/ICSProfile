As for your question, I guess you are referring to PEM (the memory acquisition framework), not the control-logic attack presented in the paper, right?
Nauman used the source code in the git repo (https://gitlab.com/hyunguk/m221) to acquire the memory from the M221 PLC. 
Let me try to explain the detailed step as much as possible.

1- We can first get the start and end addresses of the control-logic code block using "m221_get_info_py". 

2- Then, overwrite the last byte of the code (which should be 0x02 indicating the return instruction) with a duplicator, 
which copies a chunk from non-protocol-mapped space to protocol-mapped space.

3- You can use "m221_write_mem.py" to overwrite the last byte with a duplicator.
For example, the following duplicator will copy a 68KB chunk from the memory address 0x0 to the destination address 0x7030000. 
https://gitlab.com/hyunguk/m221/-/blob/master/pem/duplicators/dup_0_ffff.s

4- Then, you can read the chunk from 0x7030000 over a network using "m221_read_mem.py".

5- You can iterate this procedure with different duplicators to acquire the entire memory space.

6- Based on the below memory map, we assume the External RAM (0x7000000~0x707FFFF) is protocol-mapped space 
while the other areas are non-protocol-mapped space.