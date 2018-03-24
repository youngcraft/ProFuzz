from scapy.packet import Packet
from scapy.fields import FlagsField
class FlagsTest(Packet):
	fields_desc = [FlagsField("flags", 0, 8, ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"])]

FlagsTest(flags=9).show2()


