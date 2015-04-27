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

from struct import pack
from hashlib import sha256
from Crypto.Cipher import AES
import hmac

__all__ = ['Milenage', 'xor_string', 'KDF', 'make_OPc',
           'conv_C2', 'conv_C3', 'conv_C4', 'conv_C5', 'conv_A2', 'conv_A3',
           'conv_A4', 'conv_A7']

###
# support functions
###

def _log(msg=''):
    print('[Milenage] %s' % msg)

def xor_string(s1, s2):
    return ''.join(map(chr, [ord(s1[i])^ord(s2[i]) for i in \
                             range(min(len(s1), len(s2)))] ))

def rotate(r, s):                             
    # align rotation value to 8-bit multiple for working on byte
    r = r // 8
    res = []
    for i in range( len(s) ):
        res.append( s[(i+r)%len(s)] )
    return ''.join(res)

def make_OPc( K, OP ):
    # OP parameter derivation
    return xor_string( AES.new( K, AES.MODE_ECB ).encrypt( OP ), OP )

def KDF( K, S ):
    # 3GPP Key Derivation Function
    # defined in TS 33.220:
    # hmac-sha256( Key, S )
    return hmac.new( K, S, sha256 ).digest()

###
# 3GPP authentication algorithm
###

class Milenage:

    ######################
    # OPERATOR CONSTANTS #
    ######################
    # define operator constants for the Milenage framework

    c1 = 15 * '\x00' + '\x00' #  128 bits
    c2 = 15 * '\x00' + '\x01' #  128 bits
    c3 = 15 * '\x00' + '\x02' #  128 bits
    c4 = 15 * '\x00' + '\x04' #  128 bits
    c5 = 15 * '\x00' + '\x08' #  128 bits

    r1 = 0x40
    r2 = 0x00
    r3 = 0x20
    r4 = 0x40
    r5 = 0x60
    
    def __init__(self, \
        OP='\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'):
        self.OP = OP
    
    ######################
    # MILENAGE FUNCTIONS #
    ######################
    
    def f1( self, K, RAND, SQN, AMF ):
        # output MAC_A[8]
        
        if len(K) != 16 \
        or len(RAND) != 16 \
        or len(SQN) != 6 \
        or len(AMF) != 2:
            _log('[WNG] K[16] or RAND[16] or SQN[6] or AMF[2]: '\
                 'not the right length')
            return -1
        
        input = ( SQN + AMF + SQN + AMF )
        
        OPc = make_OPc( K, self.OP )
        temp = AES.new( K, AES.MODE_ECB ).encrypt( xor_string(RAND, OPc) )
        temp = xor_string(temp, xor_string(self.c1, rotate(self.r1, xor_string(input, OPc))))
        
        MAC_A = xor_string( OPc, AES.new(K, AES.MODE_ECB).encrypt(temp) )
        return MAC_A[:8]

    def f1star( self, K, RAND, SQN, AMF ):
        # output MAC_S[8]
        
        if len(K) != 16 \
        or len(RAND) != 16 \
        or len(SQN) != 6 \
        or len(AMF) != 2:
            _log('[WNG] K[16] or RAND[16] or SQN[6] or AMF[2]: '\
                 'not the right length')
            return -1
        
        input = ( SQN + AMF + SQN + AMF )
        
        OPc = make_OPc( K, self.OP )
        temp = AES.new( K, AES.MODE_ECB ).encrypt( xor_string(RAND, OPc) )
        temp = xor_string(temp, 
                          xor_string(self.c1,
                                     rotate(self.r1, xor_string(input, OPc))))
        
        MAC_S = xor_string( OPc, AES.new(K, AES.MODE_ECB).encrypt(temp) )
        return MAC_S[8:16]

    def f2345( self, K, RAND ):
        # output RES[8], CK[16], IK[16], AK[6]
        
        if len(K) != 16 \
        or len(RAND) != 16:
            _log('[WNG] K[16] or RAND[16] does not have the right length')
            return -1
        
        OPc = make_OPc( K, self.OP )
        
        out2 = xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(self.c2, \
                    rotate(self.r2, \
                    xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(OPc, RAND)))))))
        RES, AK = out2[8:16], out2[:6] 
        
        out3 = xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(self.c3, \
                    rotate(self.r3, \
                    xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(OPc, RAND)))))))
        CK = out3[:16]
        
        out4 = xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(self.c4, \
                    rotate(self.r4, \
                    xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(OPc, RAND)))))))
        IK = out4[:16]
        
        return RES, CK, IK, AK

    def f5star( self, K, RAND ):
        # output AK[6]
        
        if len(K) != 16 \
        or len(RAND) != 16:
            _log('[WNG] K[16] or RAND[16] does not have the right length')
            return -1
        
        OPc = make_OPc( K, self.OP )
        
        out5 = xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(self.c5, \
                    rotate(self.r5, \
                    xor_string(OPc, \
                    AES.new(K, AES.MODE_ECB).encrypt( \
                    xor_string(OPc, RAND)))))))
        AK = out5[:6]
        return AK

###
# conversion functions
###

# Some 2G <-> 3G conversion functions
# see TS 33.102, 6.8.1.2 and annex C
# for 3G subscribers attaching on a 2G network or 2G handsets attaching a 
# 3G network
#
# SRES (2G handset response) from XRES (3G USIM response)
def conv_C2(XRES=16*'\0'):
    # adapt XRES length
    len_xres = len(XRES)
    if len_xres < 4:
        _log('Your XRES is damned too short [<4]')
        return
    elif 4 <= len_xres < 16:
        XRES += (16-len_xres)*'\0'
    elif len_xres > 16:
        XRES = XRES[:16]
    # xor the 4 parts of 4 bytes each
    return xor_string(xor_string(xor_string(XRES[:4], XRES[4:8]),
                                  XRES[8:12]),
                       XRES[12:16])

# Kc (2G handset ciphering key) from CK / IK (3G USIM keys)
def conv_C3(CK=16*'\0', IK=16*'\0'):
    if len(CK) != 16 or len(IK) != 16:
        _log('Your CK / IK are not the right length [16]')
        return
    return xor_string(xor_string(xor_string(CK[0:8], CK[8:16]), \
                                  IK[0:8]), \
                       IK[8:16])

# CK (3G handset ciphering key) from Kc (2G SIM key)
def conv_C4(Kc=8*'\0'):
    if len(Kc) != 8:
        _log('Your Kc is not the right length [8]')
        return
    return Kc + Kc

# IK (3G handset integrity-protection key) from Kc (2G SIM key)
def conv_C5(Kc=8*'\0'):
    if len(Kc) != 8:
        _log('Your Kc is not the right length [8]')
        return
    return xor_string(Kc[:4], Kc[4:]) + Kc + xor_string(Kc[:4], Kc[4:])

#
# Some 3G <-> LTE conversion functions
# see TS 33.401, annex A
#
# Kasme (LTE master key) from CK, IK (3G USIM key)
def conv_A2(CK=16*'\0', IK=16*'\0', sn_id=3*'\0', sqn_x_ak=6*'\0'):
    if len(CK) != 16 or len(IK) != 16:
        _log('Your CK / IK are not the right length [16]')
        return
    if len(sn_id) != 3:
        _log('Your SN_ID is not the right length [3]')
        return
    if len(sqn_x_ak) != 6:
        _log('Your SQN xor AK is not the right length [6]')
        return
    S = '\x10' + sn_id + pack('!H', len(sn_id)) + \
                 sqn_x_ak + pack('!H', len(sqn_x_ak))
    return KDF(CK+IK, S)

# KeNB (eNB AS master key) from Kasme and uplink NAS count
def conv_A3(Kasme=32*'\0', ul_nas_cnt=0):
    if len(Kasme) != 32:
        _log('Your Kasme is not the right length [32]')
        return
    if not (0 <= ul_nas_cnt < 2**24):
        _log('Your uplink NAS count is not the right value [24 bits uint]')
        return
    S = '\x11' + pack('!IH', ul_nas_cnt, 4)
    return KDF(Kasme, S)

# NH (for generating KeNB* at HO) from Kasme and SYNC
def conv_A4(Kasme=32*'\0', SYNC=32*'\0'):
    if len(Kasme) != 32:
        _log('Your Kasme is not the right length [32]')
        return
    if len(SYNC) != 32:
        _log('Your SYNC is not the right length [32]')
        return
    S = '\x12' + SYNC + '\0\x20'
    return KDF(Kasme, S)

# NAS, RRC and UP keys derivation from Kasme / KeNB
def conv_A7(KEY=32*'\0', alg_dist=0, alg_id=0):
    if len(KEY) != 32:
        _log('Your KEY is not the right length [32]')
        return
    if not (0 <= alg_dist < 256):
        _log('Your algorithm distinguisher is not the right value '\
             '[8 bits uint]')
        return
    if not (0 <= alg_id < 256):
        _log('Your algorithm identifier is not the right value '\
             '[8 bits uint]')
        return
    S = '\x15' + pack('!BHBH', alg_dist, 1, alg_id, 1)
    return KDF(KEY, S)
#
