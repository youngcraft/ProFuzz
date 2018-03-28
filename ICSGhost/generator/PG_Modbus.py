#!/usr/bin/env python

# This file is part of ProFuzz.

# ProFuzz is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ProFuzz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with ProFuzz.  If not, see <http://www.gnu.org/licenses/>.

# Authors: Dmitrijs Solovjovs, Tobias Leitenmaier, Daniel Mayer

import sys
sys.path.append('..')

from scapy.all import *
from protocol.ModbusProtocols import *

# generate the modbus through tcp
def modbus_read_coil():
	modbus_head = ModbusADURequest()
	buffer = 



def


if __name__ == '__main__':
	print 'ok'

