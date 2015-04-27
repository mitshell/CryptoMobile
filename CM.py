# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile 
# * Version : 0.1.0
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
# * File Name : CryptoMobile/CM.py
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
import sys
from math import ceil
from struct import pack, unpack
from binascii import hexlify, unhexlify
from ctypes import *

#AES CTR and ECB modes for LTE crypto are imported from pycrypto
#AES CMAC mode is implemented here from AES ECB
try:
    from Crypto.Cipher import AES
    # filter * export
    __all__ = ['CryMo', 'KASUMI', 'SNOW3G', 'ZUC', 'AES_3GPP',
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA2', 'EIA2', 'EEA3', 'EIA3']
    with_pycrypto = True
except ImportError:
    print('[WNG] [Import] Crypto.Cipher.AES from pycrypto not found\n' \
           '[-] EEA2 / EIA2 not available')
    # filter * export
    __all__ = ['CryMo', 'KASUMI', 'SNOW3G', 'ZUC', 
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA3', 'EIA3']
    with_pycrypto = False


# convinience functions: change their content if you want
def log(level='DBG', msg=''):
    # log wrapper
    print('[%s] %s' % (level, msg))

# class and exception wrapper for all crypto-mobile algorithms
class CryMo(object):
    pass

class CMException(Exception):
    pass


# GLOBAL WARNING:
# Endianness management may be messy...
# Tested successfully on x86 32 and 64 bits only
#
# compiled shared library path (.dll on windows, .so on Linux)
#
#library_path = 'C:/Python27/Lib/site-packages/CryptoMobile/'
#library_path = '/home/mich/python/CryptoMobile/'
library_path = '%s/' % os.path.dirname(os.path.abspath( __file__ ))
#
#library_suf = '.dll'
library_suf = '.so'
if sys.platform[:3] == 'win':
    library_suf = '.dll'
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

#
# 2 functions to wrap (u8 *) C objects
def write_arubyte(buf=''):
    if not isinstance(buf, str):
        raise(CMException)
    c_arubyte = (c_ubyte*len(buf))()
    for i in range(len(buf)):
        c_arubyte[i] = ord(buf[i])
    return c_arubyte

def read_arubyte(arubyte=(c_ubyte)):
    if not hasattr(arubyte, '__len__') or \
    not isinstance(arubyte, (c_ubyte*len(arubyte))):
        raise(CMException)
    return ''.join([chr(arubyte[i]) for i in range(len(arubyte))])

###
# python wrapper to Kasumi reference C code
###

class KASUMI(CryMo):
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
        key is 16 bytes string
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to UMTS bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to be ciphered / deciphered
        bitlen is a int32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    .F9(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes string
        count is uint32 integer
        fresh is uint32 integer
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to use for MAC computing
        bitlen is a uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes string
    
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
    
    def _initialize(self, key=16*'\0'):
        # arg sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        # get key value into ctype
        key_c = write_arubyte(key)
        # call C function
        self.__func_KeySchedule(key_c)
    
    def _cipher_block(self, input=8*'\0'):
        # arg sanity check
        if not isinstance(input, str) or len(input) != 8:
            raise(CMException)
        # get input value into ctype
        input_c = write_arubyte(input)
        # call C function
        self.__func_Kasumi(input_c)
        return ''.join(map(chr, input_c))
    
    def F8(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
		# the value is completely arbitrary... 
		# 16 MB should be far enough for an RRC message
        if not isinstance(data, str) or len(data) >= 16777217:
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
    
    def F9(self, key=16*'\0', count=0, fresh=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(fresh, (int, long)) or fresh < 0 or fresh >= max32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
		# the value is completely arbitrary... 
		# 16 MB should be far enough for an RRC message
        if not isinstance(data, str) or len(data) >= 16777217:
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

class SNOW3G(CryMo):
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
        key is 16 bytes string
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to UMTS bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to be ciphered / deciphered
        bitlen is uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for UMTS RRC message:
    .F9(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes string
        count is uint32 integer
        fresh is uint32 integer
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes string
    
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
    
    def _initialize(self, key=16*'\0', iv=16*'\0'):
        # arg sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(iv, str) or len(iv) != 16:
            raise(CMException)
        # get key, iv values into ctype
        key_c, iv_c = (c_uint32*4)(), (c_uint32*4)()
        for i in range(4):
            key_c[i] = unpack('!I', key[i*4:(i+1)*4])[0]
            iv_c[i] = unpack('!I', iv[i*4:(i+1)*4])[0]
        # call C function
        self.__func_Initialize(key_c, iv_c)
    
    def _generate_keystream(self, length=4):
        max32 = pow(2, 32)
        # arg sanity check
        if not isinstance(length, (int, long)) or length >= max32:
            raise(CMException)
        numw = int(ceil(length/4.0))
        # get input value into ctype
        keystream_c = (c_uint32*numw)()
        # call C function
        self.__func_GenerateKeystream(c_uint32(numw), keystream_c)
        return ''.join(map(pack, numw*['!I'], keystream_c))[:length]
    
    def F8(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or len(data) >= 16777216:
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
    
    def F9(self, key=16*'\0', count=0, fresh=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # compute bitlen if needed
        if not bitlen:
            bitlen = len(data)*8
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(fresh, (int, long)) or fresh < 0 or fresh >= max32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, (int, long)) or bitlen < 0 or \
        bitlen >= len(data)*8:
            #raise(CMException)
            bitlen = len(data)*8
        # get input values into ctype
        key_c = write_arubyte(key)
        data_c = write_arubyte(data)
        # call C function
        mac = self.__func_F9(key_c, c_uint32(count), c_uint32(fresh), \
                             c_uint32(dir), data_c, c_uint64(bitlen))
        # return processed data (MAC-I)
        return read_arubyte(mac.contents)
    
    def EIA1(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        return self.F9(key, count, bearer << 27, dir, data, bitlen)

###
# python wrapper to ZUC reference C code 
###

class ZUC(CryMo):
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
        key is 16 bytes string
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to be ciphered / deciphered
        bitlen is uint32 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for LTE RRC and NAS messages:
    .EIA3(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes string
        count is uint32 integer
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes string
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
    
    def _initialize(self, key=16*'\0', iv=16*'\0'):
        # arg sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(iv, str) or len(iv) != 16:
            raise(CMException)
        # get key, iv values into ctype
        key_c, iv_c = (c_ubyte*16)(), (c_ubyte*16)()
        for i in range(16):
            key_c[i] = ord(key[i])
            iv_c[i] = ord(iv[i])
        # call C function
        self.__func_Initialization(key_c, iv_c)
    
    def _generate_keystream(self, length=4):
        max32 = pow(2, 32)
        # arg sanity check
        if not isinstance(length, (int, long)) or length >= max32:
            raise(CMException)
        numw = int(ceil(length/4.0))
        # get input value into ctype
        keystream_c = (c_uint32*numw)()
        # call C function
        self.__func_GenerateKeystream(keystream_c, c_uint32(numw))
        return ''.join([pack('!I', w) for w in keystream_c])[:length]
    
    def EEA3(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get key
        key_c = (c_ubyte*16)()
        for i in range(16):
            key_c[i] = ord(key[i])
        # get IO messages
        numw = int(ceil(bitlen/32.0))
        in_c = (c_uint32*numw)()
        # extend data with 0 to fit into uint32 stream
        # bitlen will anyway act when calling the C function
        data = ''.join((data, '\0'*4))
        for i in range(0, numw):
            in_c[i] = unpack('!I', data[i*4:(i+1)*4])[0]
        out_c = (c_uint32*numw)()
        # call C function
        self.__func_EEA3(key_c, c_uint32(count), c_uint32(bearer), \
                    c_uint32(dir), c_uint32(bitlen), in_c, out_c)
        # return processed data (clear/cipher data)
        return ''.join([pack('!I', w) for w in out_c])[:int(ceil(bitlen/8.0))]
    
    def EIA3(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or len(data) >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > len(data)*8:
            bitlen = len(data)*8
        # get key
        key_c = (c_ubyte*16)()
        for i in range(16):
            key_c[i] = ord(key[i])
        # get IO messages
        numw = int(ceil(bitlen/32.0))
        in_c = (c_uint32*numw)()
        out_c = c_uint32()
        # extend data with 0 to fit into uint32 stream
        # bitlen will anyway act when calling the C function
        data = ''.join((data, '\0'*4))
        for i in range(0, numw):
            in_c[i] = unpack('!I', data[i*4:(i+1)*4])[0]
        # call C function
        self.__func_EIA3(key_c, c_uint32(count), c_uint32(bearer), \
                    c_uint32(dir), c_uint32(bitlen), in_c, out_c)
        # return processed data (clear/cipher data)
        return pack('!I', out_c.value)
    

###
# python wrapper to pycrypto AES
###
#
AES_key_size = 16
AES_block_size = 16
if with_pycrypto:
    # Initialize pycrypto AES block cipher constants
    AES.key_size = AES_key_size
    AES.block_size = AES_block_size
    aes_ecb = lambda key, data: AES.new(key, AES.MODE_ECB).encrypt(data)
#
xor_str = lambda a, b: ''.join(map(chr, [ord(a[i])^ord(b[i]) for i in \
                               range(min(len(a), len(b)))] ))
_pow64 = 0x10000000000000000

# Define a class for AES_CTR and AES_CMAC as specified in TS 33.401
# AES_CMAC is defined in NIST 800-38B
class AES_3GPP(CryMo):
    '''
    LTE 2nd encryption / integrity protection algorithm
    It is AES-based, working with:
        - 128 bits key and 128 bits block
        - in CTR mode for ciphering (based on pycrypto function)
        - in CMAC mode for integrity protection 
          (made from pycrypto AES-ECB function)
    
    Generator initialization and keystream generation primitives are defined in
    .AES_CMAC(K, M, Tlen, Mlen) -> MAC
        K: 16 bytes key
        M: message to MAC
        Tlen: MAC length expected (between 1 and 128 bits)
        Mlen: message length in bits (in case not byte aligned)
        MAC: produced MAC, compliant to Tlen length in bits
    
    LTE mode of operation (EEA2, EIA2)
    For ciphering messages at LTE PDCP and NAS layer:
    .EEA2(key, count, bearer, dir, data_in, bitlen) -> data_out
        key is 16 bytes string
        count is uint32 integer (or long, as it is the way python works)
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to be ciphered / deciphered
        bitlen is an integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        data_out is the result of ciperhing / deciphering
    For producing MAC-I integrity code for LTE RRC and NAS messages:
    .EIA2(key, count, fresh, dir, data_in, bitlen) -> mac
        key is 16 bytes string
        count is uint32 integer
        bearer is unsigned integer limited to LTE bearers (coded on 5 bits)
        dir is 0 or 1 integer depending on uploading or downloading
        data_in is a variable-length string, to use for MAC computing
        bitlen is uint64 integer, representing the length of data_in in bits
            optional to pass, depending if data_in is byte aligned
        mac is a 4 bytes string
    '''
    
    dbg_cmac = 0
    
    def __counter(self):
        if not hasattr(self, 'ctr_count'):
            self.ctr_count = 0
        else:
            self.ctr_count += 1
            if self.ctr_count == _pow64:
                self.ctr_count = 0
        cnt = ''.join((self.iv_64h, pack('!Q', self.ctr_count)))
        #print hexlify(cnt)
        return cnt
    
    def __cmac_key_sched(self, key):
        # schedule the key for potential padding
        # AES a zero input block
        L = aes_ecb(key, 16*'\0')
        if self.dbg_cmac:
            print('L: %s' % hexlify(L))
        # schedule depending of the MSB of L
        # python-fu: unpack the 128 bits register as 2 BE uint64
        Lh, Ll = unpack('!QQ', L)
        # sum both uint64 as an uint128, left-shift and filter
        K1 = (((Lh*_pow64)+Ll) << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K1 depending of the MSB of L
        if Lh & 0x8000000000000000:
             K1 ^= 0x87
        # re-shift K1 to make K2
        K2 = (K1 << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K2 depending of the MSB of K1
        if K1 & 0x80000000000000000000000000000000:
            K2 ^= 0x87
        # return 2 corresponding 16-bytes strings K1, K2
        return pack('!QQ', K1/_pow64, K1%_pow64), \
               pack('!QQ', K2/_pow64, K2%_pow64)
    
    def AES_CMAC(self, K=16*'\0', M='', Tlen=AES_block_size*8, Mlen=None):
        # prepare bit length
        if not isinstance(Mlen, (int, long)) or Mlen < 0 or Mlen > len(M)*8:
            Mlen = len(M)*8
        # truncate / zero the message if Mlen is given correctly
        else:
            M = M[:int(ceil(Mlen/8.0))]
            lastbits = (8-(Mlen%8))%8
            if lastbits:
                M = ''.join((M[:-1], \
                    chr(ord(M[-1:]) & (0x100 - (1<<lastbits))) ))
        # define parameters for iterating
        b = AES_block_size*8
        # n is useless, as we iterate directly over Mlist:
        #n = int(ceil(Mlen / float(b))) if Mlen else 1
        # K1, K2 subkeys
        K1, K2 = self.__cmac_key_sched(K)
        if self.dbg_cmac:
            print('K1: %s' % hexlify(K1))
            print('K2: %s' % hexlify(K2))
        # message divided into blocks of length b, and last Mn taken out
        Mlist = [M[i:i+AES_block_size] \
                 for i in range(0, int(ceil(Mlen/8.0)), AES_block_size)]
        #print Mlist
        if Mlist:
            Mn = Mlist.pop()
            Mnlen = Mlen % b
            # adjust last block depending of its length
            if Mnlen:
                # if M not AES blocksize-aligned:
                # NIST'way to pad: (Mn*||10^j)^K2, j = n*b-Mlen-1 ...
                # so... 1st, pad with 0
                Mn += '\0' * (16-int(ceil(Mnlen/8.0)))
                # then switch the 1st padding bit to 1 
                # in the 1st byte with padding
                pad_offset = Mnlen/8
                Mn = ''.join(( \
                    Mn[:pad_offset],
                    chr( ord(Mn[pad_offset]) + (1 << (8-((Mnlen%8)+1))) ), \
                    Mn[pad_offset+1:] ))
                #print('Mn padded: %s' % hexlify(Mn))
                # XOR Mn with subkey
                Mn = xor_str(Mn, K2)
            else:
                # if M is AES blocksize-aligned, XOR Mn with subkey:
                Mn = xor_str(Mn, K1)
        else:
            # this is for the NIST cra$*?* test vectors...
            Mn = '\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
            Mn = xor_str(Mn, K2)
        Mlist.append(Mn)
        # loop over the message to MAC it
        C = AES_block_size * '\0'
        for Mi in Mlist:
            #print('Mi: %s' % hexlify(Mi))
            C = aes_ecb(K, xor_str(C, Mi))
        # if Tlen not byte-aligned, zero out last bits of T
        T = C[:int(ceil(Tlen/8.0))]
        if Tlen%8:
            T = ''.join((T[:-1], chr(ord(T[-1])&(0xff-(1<<(8-(Tlen%8))-1)))))
        return T
    
    def EEA2(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        length = len(data)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or length >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > length*8:
            bitlen = length*8
        # if bitlen is given correctly, truncate data if needed
        else:
            data = data[:int(ceil(bitlen/8.0))]
        # build IV with highest 64 bits of the CTR counter
        self.iv_64h = pack('!II', count, (bearer<<27)+(dir<<26))
        # initialize CTR counter
        self.ctr_count = -1
        ciph = AES.new(key, AES.MODE_CTR, counter=self.__counter).encrypt(data)
        # zero out last bits of data if needed
        lastbits = (8-(bitlen%8))%8
        if lastbits:
            ciph = ''.join((ciph[:-1], \
                      chr(ord(ciph[-1:]) & (0x100 - (1<<lastbits))) ))
        return ciph
    
    def EIA2(self, key=16*'\0', count=0, bearer=0, dir=0, data='', bitlen=None):
        max32 = pow(2, 32)
        length = len(data)
        # args sanity check
        if not isinstance(key, str) or len(key) != 16:
            raise(CMException)
        if not isinstance(count, (int, long)) or count < 0 or count >= max32:
            raise(CMException)
        if not isinstance(bearer, int) or bearer < 0 or bearer >= 32:
            raise(CMException)
        if not isinstance(dir, int) or dir not in (0, 1):
            raise(CMException)
        if not isinstance(data, str) or length >= 16777216:
            raise(CMException)
        if not isinstance(bitlen, int) or bitlen < 0 or bitlen > length*8:
            bitlen = length*8
        # prepare concatenated message:
        M = ''.join(( pack('!II', count, (bearer<<27)+(dir<<26)), data))
        return self.AES_CMAC(key, M, 32, bitlen+64)

    
#
###################
# DEFINE 3GPP ALG #
# convinient for  #
# python export   #
###################
#
K = KASUMI()
S = SNOW3G()
Z = ZUC()
if with_pycrypto:
    A = AES_3GPP()
# For 3G
UEA1 = K.F8
UIA1 = K.F9
UEA2 = S.F8
UIA2 = S.F9
# For LTE
EEA1 = S.F8
EIA1 = S.EIA1
EEA3 = Z.EEA3
EIA3 = Z.EIA3
if with_pycrypto:
    EEA2 = A.EEA2
    EIA2 = A.EIA2
#
