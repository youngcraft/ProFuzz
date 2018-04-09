# coding: utf8

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = ModBus Protocol
# scapy.contrib.status = loads

# Copyright (C) 2017 Arthur Gervais, Ken LE PRADO, Sébastien Mainand, Thomas Aurel

from scapy.packet import *
from scapy.fields import *
import random
from scapy.layers.inet import *
from scapy.all import *
from ModbusProtocols import ModbusPDU01ReadCoilsRequest,ModbusADURequest
from time import sleep
'''
description: generate the packet of modbus

'''

class ModbusPacketList():
	"""
	"""
	def __init__(self,target_ip,target_port):
		# pass
		self.target_ip = target_ip
		self.target_port = target_port
		self.packet_list = []


	def request_coil_read(self):
		# IP for all transmissions
		ip = IP(dst="166.142.203.205")
		
		shortlist = [x for x in range(1,65535)]
		
		# Sets up the session with a TCP three-way handshake
		# Send the syn, receive the syn/ack
		tcp = TCP(flags='S', window=65535, sport=RandShort(), dport=502,
		          options=[('MSS', 1360), ('NOP', 1), ('NOP', 1), ('SAckOK', '')])
		synAck = sr1(ip / tcp)
		#sleep(20)
		# Send the ack
		tcp.flags = 'A'
		tcp.sport = synAck[TCP].dport
		tcp.seq = synAck[TCP].ack
		tcp.ack = synAck[TCP].seq + 1
		tcp.options = ''
		send(ip / tcp)
		
		tcp.flags = 'AP'
		adu = ModbusADURequest()
		pdu = ModbusPDU01ReadCoilsRequest()
		
		adu.transId = hex(random.choice(shortlist))
		pdu.startAddr = hex(random.choice(shortlist))
		pdu.quantity = hex(random.choice(shortlist))
		adu = adu / pdu
		tcp = tcp / adu
		packet = ip / tcp
		packet.show()
		data = sr1((ip / tcp), timeout=20)
		if data:
			data.show()
		

		# shortlist= [x for x in range(1,65536)]


		
		
		# self.packet_list.append(packet)
		# print len(self.packet_list)
	
	def request_raw_socket(self):
		import socket
		shortlist = [x for x in range(1, 65535)]
		sock = socket.socket()
		sock.connect(("166.142.203.205", 502))
		s = StreamSocket(sock)
		adu = ModbusADURequest()
		pdu = ModbusPDU01ReadCoilsRequest()
		
		adu.transId = 0xff
		startaddr = hex(random.choice(shortlist))
		print startaddr
		print type(startaddr)
		print type(0xffff)
		pdu.funcCode = 90
		pdu.startAddr = 65535
		pdu.quantity = 0xffff
		adu = adu / pdu
		adu.show()
		ans = s.sr(adu)
		ans.show()

if __name__ =='__main__':
	x = ModbusPacketList('166.142.203.205',502)
	packetl = x.request_raw_socket()
	
