# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile 
# * Version : 0.2.0
# *
# * Copyright © 2013. Benoit Michau. ANSSI.
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
# * File Name : CryptoMobile/CM_ctypes.py
# * Created : 2013-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

########################################################
# CryptoMobile python toolkit
#
# Interfaces C implementation of reference mobile cryptographic algorithms 
# to python primitives
# WARNING: mobile crypto algorithms specifications are freely available on the web, 
# but generally require license to be used in field equipments
#
# C source code from 3GPP / ETSI / GSMA / NIST web pages:
# - Kasumi (UEA1, UIA1)
# - SNOW3G (UEA2, UIA2, EEA1, EIA1)
# - ZUC (EEA3, EIA3)
# - AES (EEA2, EIA2) - from pycrypto
#######################################################

import os
from math     import ceil
from struct   import pack, unpack
from binascii import hexlify, unhexlify
from ctypes   import *
#
from .utils   import *
from .CMAC    import CMAC

try:
    from Crypto.Cipher import AES
    # filter * export
    __all__ = ['KASUMI', 'SNOW3G', 'ZUC', 'AES_3GPP',
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA2', 'EIA2', 'EEA3', 'EIA3']
    _with_pycrypto = True
except ImportError:
    print('[WNG] [Import] Crypto.Cipher.AES from pycrypto not found\n' \
           '[-] EEA2 / EIA2 not available')
    # filter * export
    __all__ = ['KASUMI', 'SNOW3G', 'ZUC', 
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA3', 'EIA3']
    _with_pycrypto = False


# GLOBAL WARNING:
# Endianness management may be messy...
# Tested successfully on x86 32 and 64 bits only
#
# compiled shared library path (.dll on windows, .so on Linux)
library_path = '%s/' % os.path.dirname(os.path.abspath( __file__ ))
#
if sys.platform[:3] == 'win':
    library_suf = '.dll'
else:
    library_suf = '.so'
#
library_name = ['SNOW_3G', 'Kasumi', 'ZUC']

def load_lib(name=None):
    if name == None:
        libraries = [''.join((library_path, lib, library_suf)) \
                     for lib in library_name]
        # load libraries with ctypes and return them
        return map(cdll.LoadLibrary, libraries)
    elif isinstance(name, str) and name in library_name:
        return cdll.LoadLibrary(''.join((library_path, name, library_suf)))


# 2 functions to wrap (u8 *) C objects
if py_vers < 3:
    
    def write_arubyte(buf=b''):
        if not isinstance(buf, bytes):
            raise(CMException)
        c_arubyte = (c_ubyte*len(buf))()
        for i, v in enumerate(map(ord, buf)):
            c_arubyte[i] = v
        return c_arubyte
    
    def read_arubyte(arubyte=(c_ubyte)):
        if not hasattr(arubyte, '__len__') or \
        not isinstance(arubyte, (c_ubyte*len(arubyte))):
            raise(CMException)
        return b''.join([chr(v) for v in arubyte])

else:
    
    def write_arubyte(buf=b''):
        if not isinstance(buf, bytes):
            raise(CMException)
        c_arubyte = (c_ubyte*len(buf))()
        for i, v in enumerate(buf):
            c_arubyte[i] = v
        return c_arubyte
    
    def read_arubyte(arubyte=(c_ubyte)):
        if not hasattr(arubyte, '__len__') or \
        not isinstance(arubyte, (c_ubyte*len(arubyte))):
            raise(CMException)
        return bytes(arubyte)


###
# python wrapper to Kasumi reference C code
###

class KASUMI(object):
    '''
    UMTS initial encryption / integrity protection algorithm
    It is a block cipher, working with:
        - 128 bits key
        - 64 bits block
    
    Key scheduling and ECB-mode single block cipher primitives are defined in
    ._initialize(key)
    ._cipher_block(input) -> output
    
    UMTS modes of operation are defined in F8 and F9 methods
    For ciphering messages at UMTS RLC or MAC layer:
    .F8(key, count, bearer, dir, data_in) -> data_out
        key is 16 bytes buffer
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to UMTS bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to be ciphered / deciphered
        bitlen is a int32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    .F9(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes buffer
        count is uint32 integer
        fresh is uint32 integer
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to use for MAC computing
        bitlen is a uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes buffer
    
    GSM / GPRS compatibility modes (A5/3, A5/4, GEA3, GEA4)
    are not implemented
    '''
    block_size = 8
    key_size = 16
    
    def __init__(self):
        # load library
        lib = load_lib(library_name[1])
        # prototypes C functions I/O
        self.__func_KeySchedule = lib.KeySchedule
        self.__func_KeySchedule.argtypes = [POINTER(c_ubyte)]
        self.__func_KeySchedule.restype = None
        self.__func_Kasumi = lib.Kasumi
        self.__func_Kasumi.argtypes = [POINTER(c_ubyte)]
        self.__func_Kasumi.restype = None
        self.__func_F8 = lib.f8
        self.__func_F8.argtypes = [POINTER(c_ubyte), c_uint32, c_uint32, \
                                   c_uint32, POINTER(c_ubyte), c_int]
        self.__func_F8.restype = None
        self.__func_F9 = lib.f9
        self.__func_F9.argtypes = [POINTER(c_ubyte), c_uint32, c_uint32, \
                                   c_uint32, POINTER(c_ubyte), c_int]
        self.__func_F9.restype = POINTER(c_ubyte*4)
    
    def _initialize(self, key=16*b'\0'):
        # arg sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        # get key value into ctype
        key_c = write_arubyte(key)
        # call C function
        self.__func_KeySchedule(key_c)
    
    def _cipher_block(self, input=8*b'\0'):
        # arg sanity check
        if not isinstance(input, bytes) or len(input) != 8:
            raise(CMException)
        # get input value into ctype
        input_c = write_arubyte(input)
        # call C function
        self.__func_Kasumi(input_c)
        if py_vers < 3:
            return b''.join(map(chr, input_c))
        else:
            return bytes(input_c)
    
    def F8(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
		# the value is completely arbitrary... 
		# 16 MB should be far enough for an RRC message
        if not isinstance(data, bytes) or len(data) >= 16777217:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        #log('DBG', 'F8 argtypes: %s' % self.__func_F8.argtypes)
        # get input values into ctype
        key_c = write_arubyte(key)
        data_c = write_arubyte(data)
        #log('DBG', 'F8 data_c: %s' % data_c)
        # call C function
        self.__func_F8(key_c, c_uint32(count), c_uint32(bearer), \
                       c_uint32(dir), data_c, c_int(bitlen))
        # return processed data (clear/cipher data)
        return read_arubyte(data_c)
    
    def F9(self, key=16*b'\0', count=0, fresh=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(fresh, int_types) or fresh < 0 or fresh >= MAX_UINT32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
		# the value is completely arbitrary... 
		# 16 MB should be far enough for an RRC message
        if not isinstance(data, bytes) or len(data) >= 16777217:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get input values into ctype
        key_c = write_arubyte(key)
        data_c = write_arubyte(data)
        # call C function
        mac = self.__func_F9(key_c, c_uint32(count), c_uint32(fresh), \
                             c_uint32(dir), data_c, c_int(bitlen))
        # return processed data (MAC-I)
        return read_arubyte(mac.contents)

###               
# python wrapper to SNOW3G reference C code
###

class SNOW3G(object):
    '''
    UMTS secondary encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    Generator initialization and keystream generation primitives are defined in
    ._initialize(key, iv)
    ._generate_keystream(length) -> keystream
    
    UMTS modes of operation are defined in F8 and F9 methods
    For ciphering messages at UMTS RLC or MAC layer:
    .F8(key, count, bearer, dir, data_in) -> data_out
        key is 16 bytes buffer
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to UMTS bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to be ciphered / deciphered
        bitlen is uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for UMTS RRC message:
    .F9(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes buffer
        count is uint32 integer
        fresh is uint32 integer
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes buffer
    
    LTE mode of operation (EEA1, EIA1) supported as well.
    The only difference is for EIA1: 'bearer' is replacing 'fresh',
    bearer is 5 bits only (<32)
    .EEA1(key, count, bearer, dir, data_in) -> data_out
    .EIA1(key, count, fresh, dir, data_in, bitlen) -> mac
    '''
    key_size = 16
    
    def __init__(self):
        # load library
        lib = load_lib(library_name[0])
        # prototypes C functions I/O
        self.__func_Initialize = lib.Initialize
        self.__func_Initialize.argtypes = [(c_uint32*4), (c_uint32*4)]
        self.__func_Initialize.restype = None
        self.__func_GenerateKeystream = lib.GenerateKeystream
        self.__func_GenerateKeystream.argtypes = [c_uint32, POINTER(c_uint32)]
        self.__func_GenerateKeystream.restype = None
        self.__func_F8 = lib.f8
        self.__func_F8.argtypes = [POINTER(c_ubyte), c_uint32, c_uint32, \
                                   c_uint32, POINTER(c_ubyte), c_uint32]
        self.__func_F8.restype = None
        self.__func_F9 = lib.f9
        self.__func_F9.argtypes = [POINTER(c_ubyte), c_uint32, c_uint32, \
                                   c_uint32, POINTER(c_ubyte), c_uint64]
        self.__func_F9.restype = POINTER(c_ubyte*4)
    
    def _initialize(self, key=16*b'\0', iv=16*b'\0'):
        # arg sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(iv, bytes) or len(iv) != 16:
            raise(CMException)
        # get key, iv values into ctype
        key_c, iv_c = (c_uint32*4)(), (c_uint32*4)()
        for i in range(4):
            key_c[i] = unpack('>I', key[i*4:(i+1)*4])[0]
            iv_c[i] = unpack('>I', iv[i*4:(i+1)*4])[0]
        # call C function
        self.__func_Initialize(key_c, iv_c)
    
    def _generate_keystream(self, length=4):
        # arg sanity check
        if not isinstance(length, int_types) or length >= MAX_UINT32:
            raise(CMException)
        numw = int(ceil(length/4.0))
        # get input value into ctype
        keystream_c = (c_uint32*numw)()
        # call C function
        self.__func_GenerateKeystream(c_uint32(numw), keystream_c)
        return pack('>' + numw*'I', *keystream_c)[:length]
    
    def F8(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8   
        #log('DBG', 'F8 argtypes: %s' % self.__func_F8.argtypes)
        # get input values into ctype
        key_c = write_arubyte(key)
        data_c = write_arubyte(data)
        #log('DBG', 'F8 data_c: %s' % data_c)
        # call C function
        self.__func_F8(key_c, c_uint32(count), c_uint32(bearer), \
                       c_uint32(dir), data_c, c_uint32(bitlen))
        # return processed data (clear/cipher data)
        return read_arubyte(data_c)
    
    def F9(self, key=16*b'\0', count=0, fresh=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(fresh, int_types) or fresh < 0 or fresh >= MAX_UINT32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get input values into ctype
        key_c = write_arubyte(key)
        data_c = write_arubyte(data)
        # call C function
        mac = self.__func_F9(key_c, c_uint32(count), c_uint32(fresh), \
                             c_uint32(dir), data_c, c_uint64(bitlen))
        # return processed data (MAC-I)
        return read_arubyte(mac.contents)
    
    def EIA1(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        return self.F9(key, count, bearer << 27, dir, data, bitlen)

###
# python wrapper to ZUC reference C code 
###

class ZUC(object):
    '''
    LTE 3rd encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    Generator initialization and keystream generation primitives are defined in
    ._initialize(key, iv)
    ._generate_keystream(length) -> keystream
    
    LTE mode of operation (EEA3, EIA3)
    For ciphering messages at LTE PDCP and NAS layer:
    .EEA3(key, count, bearer, dir, data_in) -> data_out
        key is 16 bytes buffer
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to be ciphered / deciphered
        bitlen is uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for LTE RRC and NAS messages:
    .EIA3(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes buffer
        count is uint32 integer
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes buffer
    '''
    key_size = 16
    
    def __init__(self):
        # load library
        lib = load_lib(library_name[2])
        # prototypes C functions I/O
        self.__func_Initialization = lib.Initialization
        self.__func_Initialization.argtypes = \
            [POINTER(c_ubyte), POINTER(c_ubyte)]
        self.__func_Initialization.restype = None
        self.__func_GenerateKeystream = lib.GenerateKeystream
        self.__func_GenerateKeystream.argtypes = [POINTER(c_uint32), c_uint32]
        self.__func_GenerateKeystream.restype = None
        self.__func_EEA3 = lib.EEA3
        self.__func_EEA3.argtypes = \
            [POINTER(c_ubyte), c_uint32, c_uint32, c_uint32, c_uint32,
             POINTER(c_uint32), POINTER(c_uint32)]
        self.__func_EEA3.restype = None
        self.__func_EIA3 = lib.EIA3
        self.__func_EIA3.argtypes = \
            [POINTER(c_ubyte), c_uint32, c_uint32, c_uint32, c_uint32,
             POINTER(c_uint32), POINTER(c_uint32)]
        self.__func_EIA3.restype = None
    
    def _initialize(self, key=16*b'\0', iv=16*b'\0'):
        # arg sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(iv, bytes) or len(iv) != 16:
            raise(CMException)
        # get key, iv values into ctype
        key_c, iv_c = (c_ubyte*16)(), (c_ubyte*16)()
        if py_vers < 3:
            for i in range(16):
                key_c[i] = ord(key[i])
                iv_c[i] = ord(iv[i])
        else:
            for i in range(16):
                key_c[i] = key[i]
                iv_c[i] = iv[i]
        # call C function
        self.__func_Initialization(key_c, iv_c)
    
    def _generate_keystream(self, length=4):
        # arg sanity check
        if not isinstance(length, int_types) or length >= MAX_UINT32:
            raise(CMException)
        numw = int(ceil(length/4.0))
        # get input value into ctype
        keystream_c = (c_uint32*numw)()
        # call C function
        self.__func_GenerateKeystream(keystream_c, c_uint32(numw))
        return pack('>' + numw*'I', *keystream_c)[:length]
    
    def EEA3(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get key
        key_c = (c_ubyte*16)()
        if py_vers < 3:
            for i in range(16):
                key_c[i] = ord(key[i])
        else:
            for i in range(16):
                key_c[i] = key[i]
        # get IO messages
        numw = int(ceil(bitlen/32.0))
        in_c = (c_uint32*numw)()
        # truncate or extend data with 0 to fit into uint32 stream
        # bitlen will anyway act when calling the C function
        if len(data) > 4*numw:
            data = data[:4*numw]
        elif len(data) < 4*numw:
            data += ((4*numw)-len(data)) * b'\0'
        for i, v in enumerate(unpack('>' + numw*'I', data)):
            in_c[i] = v
        out_c = (c_uint32*numw)()
        # call C function
        self.__func_EEA3(key_c, c_uint32(count), c_uint32(bearer), \
                    c_uint32(dir), c_uint32(bitlen), in_c, out_c)
        # return processed data (clear/cipher data)
        return pack('>' + numw*'I', *out_c)[:int(ceil(bitlen/8.0))]
    
    def EIA3(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get key
        key_c = (c_ubyte*16)()
        if py_vers < 3:
            for i in range(16):
                key_c[i] = ord(key[i])
        else:
            for i in range(16):
                key_c[i] = key[i]
        # get IO messages
        numw = int(ceil(bitlen/32.0))
        in_c = (c_uint32*numw)()
        out_c = c_uint32()
        # truncate or extend data with 0 to fit into uint32 stream
        # bitlen will anyway act when calling the C function
        if len(data) > 4*numw:
            data = data[:4*numw]
        elif len(data) < 4*numw:
            data += ((4*numw)-len(data)) * b'\0'
        for i, v in enumerate(unpack('>' + numw*'I', data)):
            in_c[i] = v
        # call C function
        self.__func_EIA3(key_c, c_uint32(count), c_uint32(bearer), \
                    c_uint32(dir), c_uint32(bitlen), in_c, out_c)
        # return processed data (clear/cipher data)
        return pack('!I', out_c.value)
    

###
# python wrapper to pycrypto AES
###
if _with_pycrypto:
    # Initialize pycrypto AES block cipher constants
    AES.key_size = 16
    AES.block_size = 16
    aes_ecb = lambda key, data: AES.new(key, AES.MODE_ECB).encrypt(data)

# Define a class for AES_CTR and AES_CMAC as specified in TS 33.401
# AES_CMAC is defined in NIST 800-38B
class AES_3GPP(object):
    '''
    LTE 2nd encryption / integrity protection algorithm
    It is AES-based, working with:
        - 128 bits key and 128 bits block
        - in CTR mode for ciphering (based on pycrypto function)
        - in CMAC mode for integrity protection 
    
    LTE mode of operation (EEA2, EIA2)
    For ciphering messages at LTE PDCP and NAS layer:
    .EEA2(key, count, bearer, dir, data_in, bitlen) -> data_out
        key is 16 bytes buffer
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to be ciphered / deciphered
        bitlen is an integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for LTE RRC and NAS messages:
    .EIA2(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes buffer
        count is uint32 integer
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length bytes buffer, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes buffer
    '''
    
    dbg_cmac = 0
    
    def __count(self):
        if not hasattr(self, '_ctr_count'):
            self._ctr_count = 0
        else:
            self._ctr_count += 1
            if self._ctr_count == MAX_UINT64:
                self._ctr_count = 0
        return self._iv_64h + pack('>Q', self._ctr_count)
    
    def EEA2(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # if bitlen is given correctly, truncate data if needed
        else:
            data = data[:int(ceil(bitlen/8.0))]
        # build IV with highest 64 bits of the CTR counter
        self._iv_64h = pack('>II', count, (bearer<<27)+(dir<<26))
        # initialize CTR counter
        self._ctr_count = -1
        enc = AES.new(key, AES.MODE_CTR, counter=self.__count).encrypt(data)
        # zero out last bits of data if needed
        lastbits = (8-(bitlen%8))%8
        if lastbits:
            # zero last bits
            if py_vers < 3:
                return enc[:-1] + chr(ord(enc[-1]) & (0x100 - (1<<lastbits)))
            else:
                return enc[:-1] + bytes([enc[-1] & (0x100 - (1<<lastbits))])
        else:
            return enc
    
    def EIA2(self, key=16*b'\0', count=0, bearer=0, dir=0, data=b'', bitlen=None):
        # args sanity check
        if not isinstance(key, bytes) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, int_types) or count < 0 or count >= MAX_UINT32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, bytes) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # prepare concatenated message:
        M = pack('>II', count, (bearer<<27)+(dir<<26)) + data
        cmac = CMAC(key, AES, Tlen=32)
        return cmac.cmac(M, 64+bitlen)


###################
# DEFINE 3GPP ALG #
# convinient for  #
# python export   #
###################
#
_K = KASUMI()
_S = SNOW3G()
_Z = ZUC()
if _with_pycrypto:
    _A = AES_3GPP()
# For 3G
UEA1 = _K.F8
UIA1 = _K.F9
UEA2 = _S.F8
UIA2 = _S.F9
# For LTE
EEA1 = _S.F8
EIA1 = _S.EIA1
EEA3 = _Z.EEA3
EIA3 = _Z.EIA3
if _with_pycrypto:
    EEA2 = _A.EEA2
    EIA2 = _A.EIA2
