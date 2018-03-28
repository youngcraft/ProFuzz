# coding: utf8


import sys
import socket
import pymongo
from scapy import *
from scapy.all import *
from PacketsGenerator import *
from optparse import OptionParser

class monitor():

	def __init__(self,target_ip,target_port,checker):
		assert type(target_ip) == str
		assert type(target_port) == int
		self.target_ip = target_ip
		self.target_port = target_port
		self.checker = checker

	def _heartbeat(self, checker,):
		pass

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

	def ARP_test(self):
		p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_ip)
		ans ,unans= srp(p)
		ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))
		print p

	def ICMP_test(self):
		pass

	def TCP_test(self):
		pass

	def UDP_test(self):
		pass

	def function_test(self,func):
		pass






class Sniffer():

	def __init__(self):
		self.stopSniff = False
		self.threads = 0

	# sends  frames and starts sniffer to find answer
	def fuzzerWithSniffer(self,packetList, interface):
		conf.iface = interface
		thread.start_new_thread(self.sniffer, (packetList[0].dst, interface))

		for packet in packetList:
			sendp(packet)
			continue

		self.stopSniff = True
		# wait until sniff thread is ready
		while threads != 0:
			pass


	def sniffer(self,filter="", interface="eth0"):
		global threads
		threads = 1
		print "sniffing on interface ", interface, " - filtering for ", filter
		snf = sniff(iface=interface, stopper=self.stopSniffing, stopperTimeout=1)
		# 开始监控网卡，把数据写入到日志系统
		pkts = ""
		for x in snf:
			if (filter in str(x.show)):
				# TODO: adjust filtering: change src with dst
				pkts += str(x.summary)
				pkts += "\n"
		output = open("logs/%s(%s).txt" % (time.strftime("%Y-%m-%d_%H:%M", time.localtime()), filter), "a")
		output.write(str(pkts))
		output.close()
		threads = 0


	def stopSniffing(self):
		return self.stopSniff







if __name__=="__main__":
	a = monitor(target_ip='192.168.0.1',target_port=80,checker=None)
	a.ARP_test()

