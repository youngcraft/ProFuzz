# coding: utf8


import socket
import pymongo
from scapy import *

class monitor:


	def __init__(self,target_ip,target_port,checker):
		assert type(target_ip) == str
		assert type(target_port) == int
		self.target_ip = target_ip
		self.target_port = target_port
		self.checker = checker

	def _heartbeat(self, checker,):
		if checker == 'modbus':
			pass
		elif checker == 's7':
			pass
		elif checker == 'profinet':
			pass
		elif checker == ''

	def _send_packet(self, pkt_dict):
		# 发送数据包到目标端口
		# 一般采用10个数据包
		# pkt_dict = {
		#   'sign-1':[...],
		#   'sign-2':[...],
 		#   'sign-3':[...],
		#   'sign-4':[...],
		#}
		for line in pkt_dict.keys():
			send_line = pkt_dict[line]
			ans,unans = srp(send_line)











if __name__=="__main__":
	pass

