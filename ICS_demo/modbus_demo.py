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
from scapy.layers.inet import *
from scapy.all import *
from ModbusProtocols import *

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

		shortlist= [x for x in range(1,65536)]

		base = ModbusADURequest()
		read_coil = ModbusPDU01ReadCoilsRequest()

		base.transId = hex(random.choice(shortlist))
		read_coil.startAddr = hex(random.choice(shortlist))
		read_coil.quantity = hex(random.choice(shortlist))

		self.packet_list.append(IP(dst=self.target_ip)/TCP(dport=502)/base/read_coid)


if __name__ =='__main__':
	x = ModbusPacketList('166.142.203.205',502)
	for i in x:
		ans,unans = sr(i)

		print ans
		print unans

