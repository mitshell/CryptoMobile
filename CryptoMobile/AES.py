# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile 
# * Version : 0.3
# *
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : CryptoMobile/AES.py
# * Created : 2020-01-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = ['AES_CTR', 'AES_ECB']

from struct import pack, unpack

from .utils import *

# this is a wrapper around few Python cryptographic libraries that support AES
# pycrypto (which seems unmaintained since 2014 / 2015)
# pycryptodome, which is a fork of pycrypto
# cryptography, which is a wrapper around openssl


# try to load pycrypto
try:
    from Crypto.Cipher import AES as AES_pycrypto
except ImportError:
    _with_pycrypto = False
else:
    _with_pycrypto = True


# try to load pycryptodome
try:
    from Cryptodome.Cipher import AES as AES_pycryptodome
except ImportError:
    _with_pycryptodome = False
else:
    _with_pycryptodome = True


# try to load cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    _with_cryptography = False
else:
    _with_cryptography = True
    _backend = default_backend()


# backend disablement
#_with_pycrypto      = False
#_with_pycryptodome  = False
#_with_cryptography  = False


#------------------------------------------------------------------------------#
# AES ECB mode (for Milenage and CMAC mode)
#------------------------------------------------------------------------------#

class AES_ECB_pycrypto(object):
    """AES in ECB mode"""
    
    block_size = 16
    
    def __init__(self, key):
        """initialize AES in ECB mode with the given key"""
        self.aes = AES_pycrypto.new(key, AES_pycrypto.MODE_ECB)
    
    def encrypt(self, data):
        """encrypt data with the key set at initialization"""
        return self.aes.encrypt(data)


class AES_ECB_pycryptodome(object):
    """AES in ECB mode"""
    
    block_size = 16
    
    def __init__(self, key):
        """initialize AES in ECB mode with the given key"""
        self.aes = AES_pycryptodome.new(key, AES_pycryptodome.MODE_ECB)
    
    def encrypt(self, data):
        """encrypt data with the key set at initialization"""
        return self.aes.encrypt(data)


class AES_ECB_cryptography(object):
    """AES in ECB mode"""
    
    block_size = 16
    
    def __init__(self, key):
        """initialize AES in ECB mode with the given key"""
        self.aes = Cipher(algorithms.AES(key), modes.ECB(), backend=_backend).encryptor()
    
    def encrypt(self, data):
        """encrypt data with the key set at initialization"""
        return self.aes.update(data)


#------------------------------------------------------------------------------#
# AES CTR mode (for EEA2)
#------------------------------------------------------------------------------#

class AES_CTR_pycrypto(object):
    """AES in CTR mode"""
    
    block_size = 16
    
    def __init__(self, key, nonce, cnt=0):
        """initialize AES in ECB mode with the given key and nonce buffer
        
        key  : 16 bytes buffer
        nonce: 8 most significant bytes buffer of the counter initial value
               counter will be incremented starting at 0
        cnt  : uint64, 8 least significant bytes value of the counter
               default is 0
        """
        self.cnt_hi = nonce
        self.cnt_lo = cnt
        self.aes = AES_pycrypto.new(
            key,
            AES_pycrypto.MODE_CTR,
            counter=self.__cnt)
    
    def __cnt(self):
        cnt = self.cnt_hi + pack('>Q', self.cnt_lo)
        self.cnt_lo += 1
        if self.cnt_lo == MAX_UINT64:
            self.cnt_lo = 0
        return cnt
    
    def encrypt(self, data):
        """encrypt / decrypt data with the key and IV set at initialization"""
        return self.aes.encrypt(data)
    
    decrypt = encrypt


class AES_CTR_pycryptodome(object):
    """AES in CTR mode"""
    
    block_size = 16
    
    def __init__(self, key, nonce, cnt=0):
        """initialize AES in ECB mode with the given key and nonce buffer
        
        key  : 16 bytes buffer
        nonce: 8 most significant bytes buffer of the counter initial value
               counter will be incremented starting at 0
        cnt  : uint64, 8 least significant bytes value of the counter
               default is 0
        """
        self.aes = AES_pycryptodome.new(
            key,
            AES_pycryptodome.MODE_CTR,
            nonce=nonce,
            initial_value=cnt)
    
    def encrypt(self, data):
        """encrypt / decrypt data with the key and IV set at initialization"""
        return self.aes.encrypt(data)
    
    decrypt = encrypt


class AES_CTR_cryptography(object):
    """AES in CTR mode"""
    
    block_size = 16
    
    def __init__(self, key, nonce, cnt=0):
        """initialize AES in ECB mode with the given key and nonce buffer
        
        key  : 16 bytes buffer
        nonce: 8 most significant bytes buffer of the counter initial value
               counter will be incremented starting at 0
        cnt  : uint64, 8 least significant bytes value of the counter
               default is 0
        """
        self.aes = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce + pack('>Q', cnt)),
            backend=_backend).encryptor()
    
    def encrypt(self, data):
        """encrypt / decrypt data with the key and IV set at initialization"""
        return self.aes.update(data)
    
    decrypt = encrypt


#------------------------------------------------------------------------------#
# AES backend selection
#------------------------------------------------------------------------------#

if _with_pycrypto:
    AES_ECB = AES_ECB_pycrypto
    AES_CTR = AES_CTR_pycrypto

elif _with_pycryptodome:
    AES_CTR = AES_CTR_pycryptodome
    AES_ECB = AES_ECB_pycryptodome

elif _with_cryptography:
    AES_CTR = AES_CTR_cryptography
    AES_ECB = AES_ECB_cryptography

else:
    raise(ImportError('missing AES backend: requires cryptography, pycryptodome or pycrypto'))

#print('AES backend: %s, %s' % (AES_ECB.__name__, AES_CTR.__name__))
