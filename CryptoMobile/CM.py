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
# * File Name : CryptoMobile/CM.py
# * Created : 2017-07-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from struct   import pack, unpack
#
from pykasumi import *
from pysnow   import *
from pyzuc    import *
from .utils   import *
from .CMAC    import CMAC

try:
    from .AES import AES_CTR, AES_ECB
    # filter * export
    __all__ = ['KASUMI', 'SNOW3G', 'ZUC', 'AES_3GPP',
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA2', 'EIA2', 'EEA3', 'EIA3']
    _with_aes = True
except ImportError as err:
    print(err)
    print('EEA2 / EIA2 not available')
    # filter * export
    __all__ = ['KASUMI', 'SNOW3G', 'ZUC', 
               'UEA1', 'UIA1', 'UEA2', 'UIA2',
               'EEA1', 'EIA1', 'EEA3', 'EIA3']
    _with_aes = False


class KASUMI(object):
    """UMTS primary encryption / integrity protection algorithm
    It is a block cipher, working with:
        - 128 bits key
        - 64 bits block
    
    
    Key scheduling and ECB-mode single block cipher primitives are defined with
    methods:
    
    _initialize(key [16 bytes]) -> None
    
    _cipher_block(input [8 bytes]) -> output [8 bytes]
    
    
    For securing radio frames at UMTS RLC or MAC layer, UMTS modes of operation 
    are defined in F8 and F9 methods:
    
    F8(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an UMTS bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    F9(key [16 bytes], count [uint32], fresh [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    
    
    GSM / GPRS compatibility modes (A5/3, A5/4, GEA3, GEA4, GIA4) are not implemented
    """
    block_size = 8
    key_size   = 16
    
    def _keyschedule(self, key):
        try:
            return kasumi_keyschedule(key)
        except ValueError as err:
            raise(CMException(err))
    
    _initialize = _keyschedule
    
    def _kasumi(self, data_in):
        try:
            return kasumi_kasumi(data_in)
        except ValueError as err:
            raise(CMException(err))
    
    _cipher_block = _kasumi
    
    def F8(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return kasumi_f8(key, count, bearer, dir, data_in, bitlen)
        except ValueError as err:
            raise(CMException(err))
    
    def F9(self, key, count, fresh, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= fresh < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return kasumi_f9(key, count, fresh, dir, data_in, bitlen)
        except ValueError as err:
            raise(CMException(err))
    

class SNOW3G(object):
    """UMTS secondary encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    
    Generator initialization and keystream generation primitives are defined 
    with methods:
    
    _initialize(key [16 bytes], iv [16 bytes]) -> None
    
    _generate_keystream(length [uint32]) -> keystream
    
    
    For securing radio frames at UMTS RLC or MAC layer, UMTS modes of operation 
    are defined in F8 and F9 methods:
    
    F8(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an UMTS bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    F9(key [16 bytes], count [uint32], fresh [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    
    
    LTE modes of operation (EEA1, EIA1) is supported as well: the only difference 
    is for EIA1, `bearer' is replacing `fresh' and has a max value of 31.
    EEA1 and EIA1 methods are defined:
    
    EEA1 aliases F8
    
    EIA1(key [16 bytes], count [uint32], bearer [uint5], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
    """
    iv_size  = 16
    key_size = 16
    
    def _initialize(self, key, iv):
        try:
            return snow_initialize(key, iv)
        except ValueError as err:
            raise(CMException(err))
    
    def _generate_keystream(self, length):
        if not 0 <= length < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        lw = length >> 2
        if length % 4:
            lastbytes = True
            lw += 1
        else:
            lastbytes = False
        #
        try:
            if lastbytes:
                return snow_generatekeystream(lw)[:length]
            else:
                return snow_generatekeystream(lw)
        except ValueError as err:
            raise(CMException(err))
    
    def F8(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return snow_f8(key, count, bearer, dir, data_in, bitlen)
        except ValueError as err:
            raise(CMException(err))
    
    def F9(self, key, count, fresh, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= fresh < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return snow_f9(key, count, fresh, dir, data_in, bitlen)
        except ValueError as err:
            raise(CMException(err))
    
    EEA1 = F8
    
    def EIA1(self, key, count, bearer, dir, data_in, bitlen=None):
        if not 0 <= bearer < 32:
            raise(CMException('invalid args'))
        #
        try:
            return self.F9(key, count, bearer<<27, dir, data_in, bitlen)
        except (ValueError, CMException) as err:
            raise(CMException(err))


class ZUC(object):
    """LTE 3rd encryption / integrity protection algorithm
    It is a pseudo-random generator, working with:
        - 128 bits key and 128 bits initialization vector
        - delivering a stream of 32 bits words
    
    
    Generator initialization and keystream generation primitives are defined 
    with methods:
    
    _initialize(key [16 bytes], iv [16 bytes]) -> None
    
    _generate_keystream(length [uint32]) -> keystream [bytes]
    
    
    For securing packets at the LTE PDCP and NAS layers, LTE modes of operation
    are defined in EEA3 and EIA3 methods:
    
    EEA3(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an LTE bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    EIA3(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    """
    iv_size  = 16
    key_size = 16
    
    def _initialize(self, key, iv):
        try:
            zuc_initialization(key, iv)
        except ValueError as err:
            raise(CMException(err))
    
    def _generate_keystream(self, length):
        if not 0 <= length < MAX_UINT32:
            raise(CMException('invalid args'))
        #
        lw = length >> 2
        if length % 4:
            lastbytes = True
            lw += 1
        else:
            lastbytes = False
        #
        try:
            if lastbytes:
                return zuc_generatekeystream(lw)[:length]
            else:
                return zuc_generatekeystream(lw)
        except ValueError as err:
            raise(CMException(err))
    
    def EEA3(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return zuc_eea3(key, count, bearer, dir, bitlen, data_in)
        except ValueError as err:
            raise(CMException(err))
    
    def EIA3(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer < 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        #
        try:
            return zuc_eia3(key, count, bearer, dir, bitlen, data_in)
        except ValueError as err:
            raise(CMException(err))


class AES_3GPP(object):
    """LTE 2nd encryption / integrity protection algorithm
    It is using AES with 128 bit key in CTR encryption mode and CBC-MAC integrity
    protection mode.
    
    For securing packets at the LTE PDCP and NAS layers, LTE modes of operation
    are defined in EEA2 and EIA2 methods:
    
    EEA2(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> data_out [bytes]
        
        an LTE bearer is usually coded on 5 bits
        optional bitlen argument represents the length of data_in in bits
    
    EIA2(key [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], data_in [bytes], bitlen [uint32])
        -> mac [4 bytes]
        
        optional bitlen argument represents the length of data_in in bits
    """
    
    def EEA2(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer <= 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
            lastbits = None
        else:
            lastbits = (8-(bitlen%8))%8
            blen = bitlen >> 3
            if lastbits:
                blen += 1
            if blen < len(data_in):
                data_in = data_in[:blen]
        #
        nonce = pack('>II', count, (bearer<<27)+(dir<<26))
        enc = AES_CTR(key, nonce).encrypt(data_in)
        #
        if lastbits:
            # zero last bits
            if py_vers < 3:
                return enc[:-1] + chr(ord(enc[-1]) & (0x100 - (1<<lastbits)))
            else:
                return enc[:-1] + bytes([enc[-1] & (0x100 - (1<<lastbits))])
        else:
            return enc
    
    def EIA2(self, key, count, bearer, dir, data_in, bitlen=None):
        # avoid uint32 under/overflow
        if not 0 <= count < MAX_UINT32 or \
        not 0 <= bearer <= 32:
            raise(CMException('invalid args'))
        #
        if bitlen is None:
            bitlen = 8*len(data_in)
        else:
            lastbits = (8-(bitlen%8))%8
            blen = bitlen >> 3
            if lastbits:
                blen += 1
            if blen < len(data_in):
                data_in = data_in[:blen]
        #
        M = pack('>II', count, (bearer<<27)+(dir<<26)) + data_in
        cmac = CMAC(key, AES_ECB, Tlen=32)
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
if _with_aes:
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
if _with_aes:
    EEA2 = _A.EEA2
    EIA2 = _A.EIA2
