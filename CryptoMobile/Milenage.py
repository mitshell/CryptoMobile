# −*− coding: UTF−8 −*−
#/**
# * Software Name : CryptoMobile 
# * Version : 0.3
# *
# * Copyright 2013. Benoit Michau. ANSSI.
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
# * File Name : CryptoMobile/Milenage.py
# * Created : 2013-07-13
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

########################################################
# CryptoMobile python toolkit
#
# Milenage authentication algorithm
# as proposed by ETSI SAGE for 3G authentication (AES-based)
# see 3GPP TS 35.205, 206 and 207
#######################################################

import sys
import hmac
from struct        import pack, unpack
from hashlib       import sha256
#
from .utils        import *
from .AES          import AES_ECB


__all__ = ['Milenage', 'KDF', 'make_OPc', 'xor_buf',
           'conv_C2', 'conv_C3', 'conv_C4', 'conv_C5',
           'conv_A2', 'conv_A3', 'conv_A4', 'conv_A7']


if sys.version_info[0] > 2:
    # python 3
    def rot_buf(b, r):
        """rotate buffer b by r bits
        """
        ro, rb = r>>3, r%8
        # byte-aligned rotation
        br = b[ro:] + b[:ro]
        if rb:
            # unaligned bit-rotation
            c = [ ((br[i]<<rb) & 0xff) + (br[i+1]>>(8-rb)) for i in range(len(br)-1)]
            c.append( ((br[-1]<<rb) & 0xff) + (br[0]>>(8-rb)) )
            br = bytes(c)
        return br
        
else:
    # python 2
    def rot_buf(b, r):
        """rotate buffer b by r bits
        """
        ro, rb = r>>3, r%8
        # byte-aligned rotation
        br = b[ro:] + b[:ro]
        if rb:
            # unaligned bit-rotation
            br = bytearray(br)
            c = [ ((br[i]<<rb) & 0xff) + (br[i+1]>>(8-rb)) for i in range(len(br)-1)]
            c.append( ((br[-1]<<rb) & 0xff) + (br[0]>>(8-rb)) )
            br = bytes(bytearray(c))
        return br

def rot_buf16(b, r):
    """rotate 16-bytes buffer b by r bits
    """
    ro, rb = r>>3, r%8
    # byte 
    br = b[ro:] + b[:ro]
    if rb:
        b0, b1 = unpack('>QQ', br)
        br = pack('>QQ', ((b0<<rb) & 0xffffffffffffffff) + (b1>>(64-rb)),
                         ((b1<<rb) & 0xffffffffffffffff) + (b0>>(64-rb)))
    return br

def make_OPc( K, OP ):
    """derive OP with K to produce OPc"""
    return xor_buf( AES_ECB(K).encrypt(OP), OP )

def KDF( K, S ):
    """derive S with K according to 3GPP Key Derivation Function defined in TS 33.220"""
    return hmac.new( K, S, sha256 ).digest()


###
# 3GPP authentication algorithm
###

class Milenage:
    """Milenage cryptographic functions, based on AES
    
    see 3GPP TS 35.205
    """

    ######################
    # OPERATOR CONSTANTS #
    ######################
    # defined operator constants for the Milenage framework
    # not recommended to change those
    # better playing with OP

    c1 = 15 * b'\x00' + b'\x00' #  128 bits
    c2 = 15 * b'\x00' + b'\x01' #  128 bits
    c3 = 15 * b'\x00' + b'\x02' #  128 bits
    c4 = 15 * b'\x00' + b'\x04' #  128 bits
    c5 = 15 * b'\x00' + b'\x08' #  128 bits

    r1 = 0x40 # uint8
    r2 = 0x00 # uint8
    r3 = 0x20 # uint8
    r4 = 0x40 # uint8
    r5 = 0x60 # uint8
    
    def __init__(self, OP):
        self.OP  = OP
        self.OPc = None
    
    def set_opc(self, OPc):
        """This sets OPc and saves some AES rounds in f1, f1star, f2345, f5star
        when producing several vectors for a single subscriber
        """
        self.OPc = OPc
    
    def unset_opc(self):
        self.OPc = None
    
    ######################
    # MILENAGE FUNCTIONS #
    ######################
    
    def f1(self, K, RAND, SQN, AMF, OP=None):
        """return MAC_A [8 bytes buffer] or None on error
        """
        if len(K) != 16 or len(RAND) != 16 or len(SQN) != 6 or len(AMF) != 2:
            _log('ERR', 'Milenage.f1: invalid args')
            return None
        #
        if self.OPc is not None:
            OPc = self.OPc
        elif OP is not None:
            OPc = make_OPc(K, OP)
        else:
            OPc = make_OPc(K, self.OP)
        #
        inp    = SQN + AMF + SQN + AMF
        cipher = AES_ECB(K)
        K_OPc_RAND = cipher.encrypt(xor_buf(RAND, OPc))
        #
        out1 = xor_buf(cipher.encrypt(
                       xor_buf(xor_buf(rot_buf16(xor_buf(inp, OPc),
                                                 self.r1),
                                       self.c1),
                               K_OPc_RAND)),
                       OPc)
        
        return out1[0:8]
    
    def f1star(self, K, RAND, SQN, AMF, OP=None):
        """return MAC_S [8 bytes buffer] or None on error
        """
        if len(K) != 16 or len(RAND) != 16 or len(SQN) != 6 or len(AMF) != 2:
            _log('ERR', 'Milenage.f1star: invalid args')
            return None
        #
        if self.OPc is not None:
            OPc = self.OPc
        elif OP is not None:
            OPc = make_OPc(K, OP)
        else:
            OPc = make_OPc(K, self.OP)
        #
        inp    = SQN + AMF + SQN + AMF
        cipher = AES_ECB(K)
        K_OPc_RAND = cipher.encrypt(xor_buf(RAND, OPc))
        #
        out1 = xor_buf(cipher.encrypt(
                       xor_buf(xor_buf(rot_buf16(xor_buf(inp, OPc),
                                                 self.r1),
                                       self.c1),
                               K_OPc_RAND)),
                       OPc)
        return out1[8:16]
    
    def f2345(self, K, RAND, OP=None):
        """return RES [8], CK [16], IK [16] and AK [6] bytes buffers or None on error
        """
        if len(K) != 16 or len(RAND) != 16:
            _log('ERR', 'Milenage.f2345: invalid args')
            return None
        #
        if self.OPc is not None:
            OPc = self.OPc
        elif OP is not None:
            OPc = make_OPc(K, OP)
        else:
            OPc = make_OPc(K, self.OP)
        #
        cipher = AES_ECB(K)
        K_OPc_RAND_OPc = xor_buf(cipher.encrypt(
                                 xor_buf(OPc, RAND)),
                                 OPc)
        #
        out2 = xor_buf(OPc,
                       cipher.encrypt(
                       xor_buf(rot_buf16(K_OPc_RAND_OPc,
                                         self.r2),
                               self.c2)))
        #
        out3 = xor_buf(OPc,
                       cipher.encrypt(
                       xor_buf(rot_buf16(K_OPc_RAND_OPc,
                                         self.r3),
                               self.c3)))
        #
        out4 = xor_buf(OPc,
                       cipher.encrypt(
                       xor_buf(rot_buf16(K_OPc_RAND_OPc,
                                         self.r4),
                               self.c4)))
        #
        return out2[8:16], out3, out4, out2[:6]
    
    def f5star(self, K, RAND, OP=None):
        """return AK [6 bytes buffer] or None on error
        """
        if len(K) != 16 or len(RAND) != 16:
            _log('ERR', 'Milenage.f5star: invalid args')
            return None
        #
        if self.OPc is not None:
            OPc = self.OPc
        elif OP is not None:
            OPc = make_OPc(K, OP)
        else:
            OPc = make_OPc(K, self.OP)
        #
        cipher = AES_ECB(K)
        K_OPc_RAND_OPc = xor_buf(cipher.encrypt(
                                 xor_buf(OPc, RAND)),
                                 OPc)
        #
        out5 = xor_buf(OPc,
                       cipher.encrypt(
                       xor_buf(rot_buf16(K_OPc_RAND_OPc,
                                         self.r5),
                               self.c5)))
        #
        return out5[:6]


###
# conversion functions
###

# Some 2G <-> 3G conversion functions
# see TS 33.102, 6.8.1.2 and annex C
# for 3G subscribers attaching on a 2G network 
# or 2G handsets attaching a 3G network
#
# SRES (2G handset response) from XRES (3G USIM response)
def conv_C2(XRES):
    """C2 conversion function
    
    return 2G SRES [4 bytes buffer] from
        3G XRES USIM output [4 to 16 bytes buffer]
    or None on error
    """
    len_xres = len(XRES)
    if len_xres < 4 or len_xres > 16:
        _log('ERR', 'conv_C2: invalid args')
        return None
    # adapt XRES length
    if len_xres < 16:
        XRES += (16-len_xres) * b'\0'
    # xor the 4 parts of 4 bytes each
    return xor_buf(xor_buf(xor_buf(XRES[:4], XRES[4:8]),
                           XRES[8:12]),
                   XRES[12:16])

# Kc (2G handset ciphering key) from CK / IK (3G USIM keys)
def conv_C3(CK, IK):
    """C3 conversion function
    
    return 2G Kc [8 bytes buffer] from
        3G CK and IK USIM output [16 bytes buffer each]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16:
        _log('ERR', 'conv_C3: invalid args')
        return None
    return xor_buf(xor_buf(xor_buf(CK[0:8], CK[8:16]),
                           IK[0:8]),
                   IK[8:16])

# CK (3G handset ciphering key) from Kc (2G SIM key)
def conv_C4(Kc):
    """C4 conversion function
    
    return 3G CK [16 bytes buffer] from
        2G Kc SIM output [8 bytes buffer]
    or None on error
    """
    if len(Kc) != 8:
        _log('ERR', 'conv_C4: invalid args')
        return None
    return Kc + Kc

# IK (3G handset integrity-protection key) from Kc (2G SIM key)
def conv_C5(Kc):
    """C5 conversion function
    
    return 3G IK [16 bytes buffer] from
        2G Kc SIM output [8 bytes buffer]
    or None on error
    """
    if len(Kc) != 8:
        _log('ERR', 'conv_C5: invalid args')
        return None
    XKc = xor_buf(Kc[:4], Kc[4:])
    return XKc + Kc + XKc

#
# Some 3G <-> LTE conversion functions
# see TS 33.401, annex A
#
# Kasme (LTE master key) from CK, IK (3G USIM key)
def conv_A2(CK, IK, sn_id, sqn_x_ak):
    """A2 conversion function
    
    return KASME [32 bytes buffer] from 
        3G CK and IK USIM output [16 bytes buffer each],
        SN_ID serving network identity [3 bytes buffer] and
        SQN^AK [6 bytes buffer]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16 or len(sn_id) != 3 or len(sqn_x_ak) != 6:
        _log('ERR', 'conv_A2: invalid args')
        return None
    return KDF(CK+IK, b'\x10' + sn_id + b'\0\x03' + sqn_x_ak + b'\0\x06')

# KeNB (eNB AS master key) from Kasme and uplink NAS count
def conv_A3(Kasme, ul_nas_cnt):
    """A3 conversion function
    
    return KeNB [32 bytes buffer] from
        Kasme [32 bytes buffer] and 
        UL NAS count [uint24]
    or None on error
    """
    if len(Kasme) != 32 or not (0 <= ul_nas_cnt < 16777216):
        _log('ERR', 'conv_A3: invalid args')
        return None
    return KDF(Kasme, b'\x11' + pack('>IH', ul_nas_cnt, 4))

# NH (for generating KeNB* at HO) from Kasme and SYNC
def conv_A4(Kasme, SYNC):
    """A4 conversion function
    
    return NH [32 bytes buffer] from 
        Kasme [32 bytes buffer] and 
        SYNC [32 bytes buffer]
    or None on error
    """
    if len(Kasme) != 32 or len(SYNC) != 32:
        _log('ERR', 'conv_A4: invalid args')
        return None
    return KDF(Kasme, b'\x12' + SYNC + b'\0\x20')

# NAS / RRC+UP keys derivation from Kasme / KeNB
def conv_A7(KEY, alg_dist=0, alg_id=0):
    """A7 conversion function
    
    return NAS or RRC and UP key [32 bytes buffer] from 
        KEY (Kasme or KeNB) [32 bytes buffer],
        algorithm dist [uint8] and
        algorithm id [uint8]
    or None on error
    """
    if len(KEY) != 32 or not (0 <= alg_dist < 256) or not (0 <= alg_id < 256):
        _log('ERR', 'conv_A7: invalid args')
        return None
    return KDF(KEY, b'\x15' + pack('>BHBH', alg_dist, 1, alg_id, 1))

