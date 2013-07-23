# −*− coding: UTF−8 −*−
"""
CryptoMobile: library to provide python bindings to mobile cryptographic
reference implementation. 
Copyright (C) 2013 Benoit Michau, ANSSI

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
########################################################
# CryptoMobile python toolkit
#
# Milenage authentication algorithm
# as proposed by ETSI SAGE for 3G authentication (AES-based)
# see 3GPP TS 35.205, 206 and 207
#######################################################

from Crypto.Cipher import AES

# support functions
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
            print('[WNG] K[16] or RAND[16] or SQN[6] or AMF[2]: '\
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
            print('[WNG] K[16] or RAND[16] or SQN[6] or AMF[2]: '\
                  'not the right length')
            return -1
        
        input = ( SQN + AMF + SQN + AMF )
        
        OPc = make_OPc( K, self.OP )
        temp = AES.new( K, AES.MODE_ECB ).encrypt( xor_string(RAND, OPc) )
        temp = xor_string(temp, xor_string(self.c1, rotate(self.r1, xor_string(input, OPc))))
        
        MAC_S = xor_string( OPc, AES.new(K, AES.MODE_ECB).encrypt(temp) )
        return MAC_S[8:16]

    def f2345( self, K, RAND ):
        # output RES[8], CK[16], IK[16], AK[6]
        
        if len(K) != 16 \
        or len(RAND) != 16:
            print('[WNG] K[16] or RAND[16] does not have the right length')
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
            print('[WNG] K[16] or RAND[16] does not have the right length')
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
#
