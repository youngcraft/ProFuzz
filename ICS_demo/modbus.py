# coding: utf8

import boofuzz
from boofuzz import *
'''
Modbus-TCP boofuzz python

'''
def main():
	target_host = '192.168.0.15'
	target_port = 502

	# tcp_connection = SocketConnection(host=target_host, port=target_port, proto='tcp')
	session = Session(
	        target=Target(
	            connection=SocketConnection(target_host, target_port, proto='tcp')))



	s_initialize("read_coil_memory")
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('read_coil_memory_block'):
			s_byte(0x01,name='funcCode read coil memory')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
		s_block_end('read_coil_memory_block')
	s_block_end('modbus_head')
	s_repeat("modbus_read_coil_memory",min_reps=1,max_reps=255)

	s_initialize('read_holding_registers')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('read_holding_registers_block'):
			s_byte(0x01,name='read_holding_registers')
			s_word(0x0000,name='start address')
			s_word(0x0000,name='quantity')
        s_block_end('read_holding_registers_block')
    s_block_end("modbus_head")

    # ---------------------------------------
    s_initialize('ReadDiscreteInputs')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadDiscreteInputsRequest'):
			s_byte(0x02,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
        s_block_end('ReadDiscreteInputsRequest')
    s_block_end("ReadDiscreteInputs")

    # ----------------------------------------
    s_initialize('ReadHoldingRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadHoldingRegistersRequest'):
			s_byte(0x03,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
        s_block_end('ReadHoldingRegistersRequest')
    s_block_end("ReadHoldingRegisters")

    # ----------------------------------------
    s_initialize('ReadInputRegisters')
	if s_block_start("modbus_head"):
		s_word(0x0001,name='transId',fuzzable=True)
		s_word(0x0002,name='protoId',fuzzable=False)
		s_word(0x06,name='length')
		s_byte(0xff,name='unit Identifier',fuzzable=False)
		if s_block_start('ReadInputRegistersRequest'):
			s_byte(0x04,name='funcCode',fuzzable=False)
			s_word(0x0000,name='start_address')
			s_word(0x0000,name='quantity')
        s_block_end('ReadHoldingRegistersRequest')
    s_block_end("ReadHoldingRegisters")

    #-----------------------------------------

	session.connect(s_get('modbus_read_coil_memory'))
	session.fuzz()

if __name__ == '__main__':
	main()