# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile 
# * Version : 0.3
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : CryptoMobile/utils.py
# * Created : 2017-08-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import sys
if sys.version_info[0] < 3:
    py_vers = 2
    int_types = (int, long)
else:
    py_vers = 3
    int_types = (int, )


MAX_UINT32 = 1<<32
MAX_UINT64 = 1<<64


if py_vers > 2:
    
    def xor_buf(b1, b2):
        return bytes([b1[i]^b2[i] for i in range(0, min(len(b1), len(b2)))])
    
    def int_from_bytes(b):
        return int.from_bytes(b, 'big')
    
else:
    
    def xor_buf(b1, b2):
        b1, b2 = bytearray(b1), bytearray(b2)
        return b''.join([chr(b1[i]^b2[i]) for i in range(0, min(len(b1), len(b2)))])

    def int_from_bytes(b):
        return reduce(lambda x, y: (x<<8) + y, map(ord, b))


# CryptoMobile-wide Exception handler
class CMException(Exception):
    """CryptoMobile specific exception
    """
    pass


# convinience function: change the content if required
def log(level='DBG', msg=''):
    # log wrapper
    print('[%s] %s' % (level, msg))
