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
# * File Name : CryptoMobile/conv.py
# * Created : 2020-01-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import hmac
from hashlib import sha256
from struct  import pack
from .utils  import *


__all__ = [
    'KDF',
    'conv_501_A2',
    'conv_501_A3',
    'conv_501_A4',
    'conv_501_A5',
    'conv_501_A6',
    'conv_501_A7',
    'conv_501_A8',
    ]


########################################################
# CryptoMobile python toolkit
# conversion functions and Key Derivation Functions
#######################################################


def KDF( K, S ):
    """derive S with K according to 3GPP Key Derivation Function defined in TS 33.220"""
    return hmac.new( K, S, sha256 ).digest()


def conv_501_A2(CK, IK, sn_name, sqn_x_ak):
    """A2 conversion function
    
    return K_AUSF [32 bytes buffer] from
        3G CK and IK USIM output [16 bytes buffer each],
        Serving network name [bytes buffer, e.g. b"5G:mnc001.mcc001.3gppnetwork.org"] and
        SQN^AK [6 bytes buffer]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16 or not 32 <= len(sn_name) <= 255 \
    or len(sqn_x_ak) != 6:
        log('ERR', 'conv_501_A2: invalid args')
        return None
    return KDF(CK + IK, b'\x6a' + \
                        sn_name + pack('>H', len(sn_name)) + \
                        sqn_x_ak + b'\x06')


def conv_501_A3(CK, IK, an_id, sqn_x_ak):
    """A3 conversion function
    
    return CK' and IK' [16 bytes buffer each] from
        3G CK and IK USIM output [16 bytes buffer each],
        Access network identity [bytes buffer] and
        SQN^AK [6 bytes buffer]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16 or not 6 <= len(an_id) <= 255 \
    or len(sqn_x_ak) != 6:
        log('ERR', 'conv_501_A3: invalid args')
        return None
    buf = KDF(CK + IK, b'\x20' + \
                       an_id + pack('>H', len(an_id)) + \
                       sqn_x_ak + b'\x06')
    return buf[:16], buf[16:]


def conv_501_A4(CK, IK, sn_name, rand, res):
    """A4 conversion function
    
    return RES* [16 bytes buffer each] from
        3G CK and IK USIM output [16 bytes buffer each],
        Serving network name [bytes buffer, e.g. b"5G:mnc001.mcc001.3gppnetwork.org"],
        RAND [16 bytes buffer] and
        RES [4 to 16 bytes buffer]
    or None on error
    """
    if len(CK) != 16 or len(IK) != 16 or not 32 <= len(sn_name) <= 255 \
    or len(rand) != 16 or not 4 <= len(res) <= 16:
        log('ERR', 'conv_501_A4: invalid args')
        return None
    return KDF(CK + IK, b'\x6b' + \
                        sn_name + pack('>H', len(sn_name)) + \
                        rand + b'\x00\x10' + \
                        res + pack('>H', len(res)))[16:]


def conv_501_A5(rand, res_star):
    """A5 conversion function
    
    return HRES* [16 bytes buffer] from 
        RAND [16 bytes buffer] and
        RES* [16 bytes buffer]
    of None on error
    """
    if len(rand) != 16 or len(res_star) != 16:
        log('ERR', 'conv_501_A5: invalid args')
        return None
    return sha256(rand + res_star).digest()[16:]


def conv_501_A6(KAUSF, sn_name):
    """A6 conversion function
    
    return K_SEAF [32 bytes buffer] from
        K_AUSF [32 bytes buffer] and
        Serving network name [bytes buffer, e.g. b"5G:mnc001.mcc001.3gppnetwork.org"]
    or None on error
    """
    if len(KAUSF) != 32 or not 32 <= len(sn_name) <= 255:
        log('ERR', 'conv_501_A6: invalid args')
        return None
    return KDF(KAUSF, b'\x6c' + \
                      sn_name + pack('>H', len(sn_name)))


def conv_501_A7(KSEAF, subs_id, abba):
    """A7 conversion function
    
    return K_AMF [32 bytes buffer] from
        K_SEAF [32 bytes buffer],
        Subscriber identity [bytes buffer, IMSI / NAI / GCI / GLI] and
        ABBA parameter [2 bytes buffer]
    or None on error
    """
    if len(KSEAF) != 32 or not 12 <= len(subs_id) <= 255 or len(abba) != 2:
        log('ERR', 'conv_501_A7: invalid args')
        return None
    return KDF(KSEAF, b'\x6d' + \
                      subs_id + pack('>H', len(subs_id)) + \
                      abba + b'\x00\x02')


def conv_501_A8(K, alg_type=0, alg_id=0):
    """A8 conversion function
    
    return K_NAS_enc/int or K_RRC_enc/int or K_UP_enc/int [16 or 32 bytes buffer] from
        K_AMF or K_gNB [32 bytes buffer],
        Algorithm type distinguisher [uint8,
            NAS_enc: 0x01, NAS_int: 0x02, RRC_enc: 0x03, RRC_int: 0x04, UP_enc: 0x05, UP_int: 0x06] and
        Algorithm identity [uint8]
    or None on error
    """
    if len(K) != 32 or not 0 <= alg_type <= 6 or not 0 <= alg_id <= 15:
        log('ERR', 'conv_501_A8: invalid args')
        return None
    return KDF(K, b'\x69' + \
                  pack('>BHBH', alg_type, 1, alg_id, 1))


# TODO:
# move conversion functions out of the Milenage.py module and put them here
