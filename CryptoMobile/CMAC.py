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
# * File Name : CryptoMobile/CMAC.py
# * Created : 2017-08-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from struct import pack, unpack
#
from .utils import *


class CMAC(object):
    """CMAC mode of operation as defined by NIST
    to be used with a block cipher
    
    Initialize with the key, block-cipher function and optionally MAC length.
    Run it with cmac() on the data to process.
    It returns the MAC of the expected length.
    
    e.g.
    >>> cmac = CMAC(16*b'A', AES, Tlen=64)
    >>> cmac.cmac(200*b'testing ')
    b'\xe0*\xf5x\x14\xbc\x13\x96'
    """
    
    def __init__(self, key, ciphermod, Tlen=None):
        """
        key [X bytes]: key used by the cipher algorithm set in `ciphermod'
            length X must correspond to the given ciphermod key length
        ciphermod [encryption module]: block-cipher algorithm
            must have `block_size' attribute and `__init__(key)' method,
            which returns an instance with an `encrypt(data_in)' method
        Tlen [int, optional]: requested MAC length (in bits)
        """
        # set the key
        self.key = key
        # init block cipher
        try:
            self.__init_cipher(ciphermod)
        except Exception as err:
            raise(CMException('invalid ciphermod arg, ', err))
        # schedule it (defines self.K1 and self.K2 [16 bytes])
        self.__keyschedule()
        # set MAC length
        if Tlen is None:
            self.Tlen = 8*self._blocksize
        elif not 0 < Tlen <= 8*self._blocksize:
            raise(CMException('invalid args'))
        else:
            self.Tlen = Tlen
    
    def __init_cipher(self, ciphermod):
        # set block-cipher and block size (in bits)
        self._ciphermod = ciphermod
        self._blocksize = ciphermod.block_size
        # init ECB-mode block cipher
        self._cipher = ciphermod(self.key)
        # link to its encrypt() method
        self._encrypt = self._cipher.encrypt
        
    def __keyschedule(self):
        # schedule the key for potential padding
        # encrypt a zero input block
        L = self._encrypt(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0')
        # schedule depending of the MSB of L
        # python-fu: unpack the 128 bits register as 2 BE uint64
        Lh, Ll = unpack('>QQ', L)
        # sum both uint64 as an uint128, left-shift and filter
        K1 = (((Lh<<64)+Ll) << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K1 depending of the MSB of L
        if Lh & 0x8000000000000000:
             K1 ^= 0x87
        # re-shift K1 to make K2
        K2 = (K1 << 1) & 0xffffffffffffffffffffffffffffffff
        # XOR K2 depending of the MSB of K1
        if K1 & 0x80000000000000000000000000000000:
            K2 ^= 0x87
        # set 2 corresponding 16-bytes strings K1, K2
        self.K1 = pack('>QQ', K1>>64, K1%MAX_UINT64)
        self.K2 = pack('>QQ', K2>>64, K2%MAX_UINT64)
    
    def cmac(self, data_in, data_len=None):
        """Computes the CBC-MAC over data_in, according to initialization 
        information
        
        data_in [bytes]
        data_len [int, optional]: length in bits of data_in, over wich the mac
            is computed
        """
        # prepare the input data according to the requested length (in bits)
        # of input data to be processed
        len_data_in = 8 * len(data_in)
        if data_len is None:
            data_len = len_data_in
            lastbits = 0
        elif not 0 < data_len <= len_data_in:
            raise(CMException('invalid args'))
        elif data_len < len_data_in:
            # truncate data_in according to data_len
            olen = data_len>>3
            lastbits = (8-(data_len%8))%8
            if lastbits:
                # zero last bits after data_len
                if py_vers < 3:
                    data_in = data_in[:olen] + chr( ord(data_in[olen]) & (0x100-(1<<lastbits)) )
                else:
                    data_in = data_in[:olen] + bytes( [data_in[olen] & (0x100-(1<<lastbits))] )
            else:
                data_in = data_in[:olen]
        else:
            lastbits = 0
        # data_in is splitted into Mn parts according to the block size of the ciphermod
        M = [data_in[i:i+self._blocksize] for i in range(0, len(data_in), self._blocksize)]
        if M:
            Mn = M.pop()
            Mnlen = data_len % (8*self._blocksize)
            if Mnlen:
                # M not blocksize-aligned
                # NIST'way to pad: (Mn*||10^j)^K2, j = n*b-Mlen-1 ...
                if lastbits:
                    # switch the 1st padding bit to 1 into the last byte of Mn
                    if py_vers < 3:
                        Mn = Mn[:-1] + chr( ord(Mn[-1]) + (1<<(lastbits-1)) )
                    else:
                        Mn = Mn[:-1] + bytes( [Mn[-1] + (1<<(lastbits-1))] )
                else:
                    # pad with an initial byte 0x80
                    Mn += b'\x80'
                # then pad with 0
                Mn += (16-1-(Mnlen>>3)) * b'\0'
                # xor Mn with K2
                Mn = xor_buf(Mn, self.K2)
            else:
                # M is blocksize-aligned
                # xor Mn with K1
                Mn = xor_buf(Mn, self.K1)
        else:
            # empty data_in...
            Mn = xor_buf(b'\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', self.K2)
        M.append(Mn)
        # loop over the blocks to MAC all of them
        C = self._blocksize * b'\0'
        for Mi in M:
            C = self._encrypt(xor_buf(C, Mi))
        if self.Tlen == self._blocksize:
            return C
        else:
            # truncate C
            olen = self.Tlen>>3
            T = C[:olen]
            if self.Tlen % 8:
                # zero last bits of T
                lastbits = (8-(self.Tlen%8))%8
                if py_vers < 3:
                    return T + chr(ord(C[olen]) & (0x100 - (1<<lastbits)))
                else:
                    return T + bytes([C[olen] & (0x100 - (1<<lastbits))])
            else:
                return T
