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
    'conv_501_A9',
    'conv_501_A10',
    'conv_501_A11',
    'conv_501_A12',
    'conv_501_A13',
    'conv_501_A141',
    'conv_501_A142',
    'conv_501_A151',
    'conv_501_A152',
    'conv_501_A16',
    'conv_501_A17',
    'conv_501_A18',
    'conv_501_A19',
    'conv_501_A20',
    'conv_501_A21',
    'conv_501_A22',
    'conv_501_A23',
    'test'
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
    or raise CMException
    """
    if len(CK) != 16 or len(IK) != 16 or not 32 <= len(sn_name) <= 255 \
    or len(sqn_x_ak) != 6:
        raise(CMException('conv_501_A2: invalid args'))
    return KDF(CK + IK, b'\x6a' + \
                        sn_name + pack('>H', len(sn_name)) + \
                        sqn_x_ak + b'\x00\x06')


def conv_501_A3(CK, IK, an_id, sqn_x_ak):
    """A3 conversion function
    
    return CK' and IK' [16 bytes buffer each] from
        3G CK and IK USIM output [16 bytes buffer each],
        Access network identity [bytes buffer] and
        SQN^AK [6 bytes buffer]
    or raise CMException
    """
    if len(CK) != 16 or len(IK) != 16 or not 6 <= len(an_id) <= 255 \
    or len(sqn_x_ak) != 6:
        raise(CMException('conv_501_A3: invalid args'))
    buf = KDF(CK + IK, b'\x20' + \
                       an_id + pack('>H', len(an_id)) + \
                       sqn_x_ak + b'\x00\x06')
    return buf[:16], buf[16:]


def conv_501_A4(CK, IK, sn_name, rand, res):
    """A4 conversion function
    
    return RES* [16 bytes buffer each] from
        3G CK and IK USIM output [16 bytes buffer each],
        Serving network name [bytes buffer, e.g. b"5G:mnc001.mcc001.3gppnetwork.org"],
        RAND [16 bytes buffer] and
        RES [4 to 16 bytes buffer]
    or raise CMException
    """
    if len(CK) != 16 or len(IK) != 16 or not 32 <= len(sn_name) <= 255 \
    or len(rand) != 16 or not 4 <= len(res) <= 16:
        raise(CMException('conv_501_A4: invalid args'))
    return KDF(CK + IK, b'\x6b' + \
                        sn_name + pack('>H', len(sn_name)) + \
                        rand + b'\x00\x10' + \
                        res + pack('>H', len(res)))[16:]


def conv_501_A5(rand, res_star):
    """A5 conversion function
    
    return HRES* [16 bytes buffer] from 
        RAND [16 bytes buffer] and
        RES* [16 bytes buffer]
    or raise CMException
    """
    if len(rand) != 16 or len(res_star) != 16:
        raise(CMException('conv_501_A5: invalid args'))
    return sha256(rand + res_star).digest()[16:]


def conv_501_A6(KAUSF, sn_name):
    """A6 conversion function
    
    return K_SEAF [32 bytes buffer] from
        K_AUSF [32 bytes buffer] and
        Serving network name [bytes buffer, e.g. b"5G:mnc001.mcc001.3gppnetwork.org"]
    or raise CMException
    """
    if len(KAUSF) != 32 or not 32 <= len(sn_name) <= 255:
        raise(CMException('conv_501_A6: invalid args'))
    return KDF(KAUSF, b'\x6c' + \
                      sn_name + pack('>H', len(sn_name)))


def conv_501_A7(KSEAF, subs_id, abba):
    """A7 conversion function
    
    return K_AMF [32 bytes buffer] from
        K_SEAF [32 bytes buffer],
        Subscriber identity [bytes buffer, IMSI / NAI / GCI / GLI] and
        ABBA parameter [2 bytes buffer]
    or raise CMException
    """
    if len(KSEAF) != 32 or not 12 <= len(subs_id) <= 255 or len(abba) != 2:
        raise(CMException('conv_501_A7: invalid args'))
    return KDF(KSEAF, b'\x6d' + \
                      subs_id + pack('>H', len(subs_id)) + \
                      abba + b'\x00\x02')


def conv_501_A8(K, alg_type=1, alg_id=1):
    """A8 conversion function
    
    return K_NAS_enc/int or K_RRC_enc/int or K_UP_enc/int [32 bytes buffer] from
        K_AMF or K_gNB [32 bytes buffer],
        Algorithm type distinguisher [uint8,
            NAS_enc: 0x01, NAS_int: 0x02, RRC_enc: 0x03, RRC_int: 0x04, UP_enc: 0x05, UP_int: 0x06] and
        Algorithm identity [uint8]
    or raise CMException
    
    In case the result must be 16 bytes and not 32, keep least significant bytes.
    """
    if len(K) != 32 or not 0 <= alg_type <= 6 or not 0 <= alg_id <= 15:
        raise(CMException('conv_501_A8: invalid args'))
    return KDF(K, b'\x69' + pack('>BHBH', alg_type, 1, alg_id, 1))


def conv_501_A9(KAMF, ul_nas_cnt=0, acc_type_dist=1):
    """A9 conversion function
    
    return K_gNB, K_WAGF, K_TNGF, K_TWIF or K_N3IWF [32 bytes buffer] from
        K_AMF [32 bytes buffer],
        Uplink NAS count [uint32] and
        Access type distinguisher [uint8, 3GPP access: 0x01, Non-3GPP access: 0x02]
    or raise CMException
    """
    if len(KAMF) != 32 or not 0 <= ul_nas_cnt <= 4294967295 or not 1 <= acc_type_dist <= 2:
        raise(CMException('conv_501_A9: invalid args'))
    return KDF(KAMF, b'\x6e' + pack('>IHBH', ul_nas_cnt, 4, acc_type_dist, 1))


def conv_501_A10(KAMF, sync):
    """A10 conversion function
    
    return NH [32 bytes buffer] from
        K_AMF [32 bytes buffer] and
        SYNC-input [uint32] and
    or raise CMException
    """
    if len(KAMF) != 32 or len(sync) != 32:
        raise(CMException('conv_501_A10: invalid args'))
    return KDF(KAMF, b'\x6f' + sync + b'\x00\x20')


def conv_501_A11(K, pci=0, arfcn_dl=0):
    """A11 conversion function
    
    return K_NG_RAN* for target gNB from
        KGNB or NH [32 bytes buffer],
        PCI target physicall cell-ID [uint16] and
        ARFCN-DL [uint24]
    or raise CMException
    """
    if len(K) != 32 or not 0 <= pci <= 65535 or not 0 <= arfcn_dl <= 16777216:
        raise(CMException('conv_501_A11: invalid args'))
    return KDF(K, b'\x70' +  \
                  pack('>HH', pci, 2) + \
                  pack('>IH', arfcn_dl, 3)[1:])


def conv_501_A12(K, pci=0, earfcn_dl=0):
    """A12 conversion function
    
    return K_NG_RAN* for target ng-eNB from
        KGNB or NH [32 bytes buffer],
        PCI target physicall cell-ID [uint16] and
        EARFCN-DL [uint24]
    or raise CMException
    """
    if len(K) != 32 or not 0 <= pci <= 65535 or not 0 <= earfcn_dl <= 16777216:
        raise(CMException('conv_501_A11: invalid args'))
    return KDF(K, b'\x71' +  \
                  pack('>HH', pci, 2) + \
                  pack('>IH', earfcn_dl, 3)[1:])


def conv_501_A13(KAMF, dir=1, dl_nas_cnt=0):
    """A13 conversion function
    
    return K_AMF' [32 bytes buffer] from
        K_AMF [32 bytes buffer],
        Direction [uint8, value 1] and
        Downlink NAS count [uint32]
    or raise CMException
    """
    if len(KAMF) != 32 or dir != 1 or not 0 <= dl_nas_cnt <= 4294967295:
        raise(CMException('conv_501_A13: invalid args'))
    return KDF(KAMF, b'\x72' + pack('>BHIH', dir, 1, dl_nas_cnt, 4))


def conv_501_A141(KAMF, ul_nas_cnt=0):
    """A14.1 conversion function
    
    return K_ASME' [32 bytes buffer] for 5G to EPS IDLE mobility from
        K_AMF [32 bytes buffer] and
        Uplink NAS count [uint32]
    or raise CMException
    """
    if len(KAMF) != 32 or not 0 <= ul_nas_cnt <= 4294967295:
        raise(CMException('conv_501_A141: invalid args'))
    return KDF(KAMF, b'\x73' + pack('>IH', ul_nas_cnt, 4))


def conv_501_A142(KAMF, dl_nas_cnt=0):
    """A14.2 conversion function
    
    return K_ASME' [32 bytes buffer] for 5G to EPS handovers from
        K_AMF [32 bytes buffer] and
        Downlink NAS count [uint32]
    or raise CMException
    """
    if len(KAMF) != 32 or not 0 <= dl_nas_cnt <= 4294967295:
        raise(CMException('conv_501_A142: invalid args'))
    return KDF(KAMF, b'\x74' + pack('>IH', dl_nas_cnt, 4))


def conv_501_A151(KASME, ul_nas_cnt=0):
    """A15.1 conversion function
    
    return K_AMF' [32 bytes buffer] for EPS to 5G IDLE mobility from
        K_ASME [32 bytes buffer] and
        Uplink NAS count [uint32]
    or raise CMException
    """
    if len(KASME) != 32 or not 0 <= ul_nas_cnt <= 4294967295:
        raise(CMException('conv_501_A151: invalid args'))
    return KDF(KASME, b'\x75' + pack('>IH', ul_nas_cnt, 4))


def conv_501_A152(KASME, nh):
    """A15.2 conversion function
    
    return K_AMF' [32 bytes buffer] for EPS to 5G handovers from
        K_ASME [32 bytes buffer] and
        NH [32 bytes buffer]
    or raise CMException
    """
    if len(KASME) != 32 or len(nh) != 32:
        raise(CMException('conv_501_A152: invalid args'))
    return KDF(KASME, b'\x76' + nh + b'\x00\x20')


def conv_501_A16(K, sn_cnt=0):
    """A16 conversion function
    
    return K_SN [32 bytes buffer] from
        Master node K_GNB or K_ENB [32 bytes buffer] and
        SN count [uint16]
    or raise CMException
    """
    if len(K) != 32 or not 0 <= sn_cnt <= 65535:
        raise(CMException('conv_501_A16: invalid args'))
    return KDF(K, b'\x79' + pack('>HH', sn_cnt, 2))


def conv_501_A17(KAUSF, sor_hdr, sor_cnt=0, pref_plmn=None):
    """A17 conversion function
    
    return SoR-MAC-I_AUSF [16 bytes buffer] from
        K_AUSF [32 bytes buffer],
        SoR header [bytes buffer],
        SoR counter [uint16] and
        Preferred PLMNs / Access Tech [bytes buffer, optional]
    or raise CMException
    """
    if len(KAUSF) != 32 or not 0 <= len(sor_hdr) <= 65535 or not 0 <= sor_cnt <= 65535 \
    or not (pref_plmn is None or 0 <= len(pref_plmn) <= 255):
        raise(CMException('conv_501_A17: invalid args'))
    if pref_plmn is None:
        return KDF(KAUSF, b'\x77' + \
                          sor_hdr + pack('>H', len(sor_hdr)) + \
                          pack('>HH', sor_cnt, 2))
    else:
        return KDF(KAUSF, b'\x77' + \
                          sor_hdr + pack('>H', len(sor_hdr)) + \
                          pack('>HH', sor_cnt, 2) + \
                          pref_plmn + pack('>H', len(pref_plmn)))


def conv_501_A18(KAUSF, sor_ack=1, sor_cnt=0):
    """A18 conversion function
    
    return SoR-MAC-I_UE [16 bytes buffer] from
        K_AUSF [32 bytes buffer],
        SoR acknowledgement [uint8, value 1] and
        SoR counter [uint16]
    or raise CMException
    """
    if len(KAUSF) != 32 or sor_ack != 1 or not 0 <= sor_cnt <= 65535:
        raise(CMException('conv_501_A18: invalid args'))
    return KDF(KAUSF, b'\x78' + pack('>BHHH', sor_ack, 2, sor_cnt, 2))


def conv_501_A19(KAUSF, upu_data, upu_cnt=0):
    """A19 conversion function
    
    return UPU-MAC-I_AUSF [16 bytes buffer] from
        K_AUSF [32 bytes buffer],
        UPU data [bytes buffer] and
        UPU counter [uint16]
    or raise CMException
    """
    if len(KAUSF) != 32 or not 0 <= len(upu_data) <= 65535 or not 0 <= upu_cnt <= 65535:
        raise(CMException('conv_501_A19: invalid args'))
    return KDF(KAUSF, b'\x7b' + upu_data + pack('>HHH', 2, upu_cnt, 2))


def conv_501_A20(KAUSF, upu_ack=1, upu_cnt=0):
    """A20 conversion function
    
    return UPU-MAC-I_UE [16 bytes buffer] from
        K_AUSF [32 bytes buffer],
        UPU acknowledgement [uint8, value 1] and
        UPU counter [uint16]
    or raise CMException
    """
    if len(KAUSF) != 32 or upu_ack != 1 or not 0 <= upu_cnt <= 65535:
        raise(CMException('conv_501_A20: invalid args'))
    return KDF(KAUSF, b'\x7c' + pack('>BHHH', upu_ack, 2, upu_cnt, 2))


def conv_501_A21(KAMF, dl_nas_cnt=0):
    """A21 conversion function
    
    return K_ASME_SRVCC [32 bytes buffer] from
        K_AMF [32 bytes buffer] and
        Downlink NAS count [uint32]
    or raise CMException
    """
    if len(KAMF) != 32 or not 0 <= dl_nas_cnt <= 4294967295:
        raise(CMException('conv_501_A21: invalid args'))
    return KDF(KAMF, b'\x7d' + pack('>IH', dl_nas_cnt, 4))


def conv_501_A22(KTNGF, use_type_dist=1):
    """A22 conversion function
    
    return K_TIPsec or K_TNAP [32 bytes buffer] from
        K_TNGF [32 bytes buffer] and
        Usage type distinguisher [uint8, IPsec: 0x01, TNAP: 0x02]
    or raise CMException
    """
    if len(KTNGF) != 32 or not 1 <= use_type_dist <= 2:
        raise(CMException('conv_501_A22: invalid args'))
    assert('FC not yet defined in TS 33.501')
    return KDF(KTNGF, b'', pack('>BH', use_type_dist, 1))


def conv_501_A23(KGNB, cu_ip_addr, du_ip_addr):
    """A23 conversion function
    
    return K_IAB PSK [32 bytes buffer] from
        K_GNB [32 bytes buffer],
        IAB-Donor-CU IP address [bytes buffer] and
        IAB-Node-DU IP address [bytes buffer]
    or raise CMException
    """
    if len(KGNB) != 32 or not 0 <= len(cu_ip_addr) <= 32 or not 0 <= len(du_ip_addr) <= 32:
        raise(CMException('conv_501_A23: invalid args'))
    return KDF(KGNB, b'\x83' + \
                     cu_ip_addr + pack('>H', len(cu_ip_addr)) + \
                     du_ip_addr + pack('>H', len(du_ip_addr)))



def test():
    K16 = 16 * b'\0'
    K32 = 32 * b'\0'
    net_name = b"5G:mnc001.mcc001.3gppnetwork.org"
    conv_501_A2(K16, K16, net_name, 6 * b'\0')
    conv_501_A3(K16, K16, net_name, 6 * b'\0')
    conv_501_A4(K16, K16, net_name, K16, K16)
    conv_501_A5(K16, K16)
    conv_501_A6(K32, net_name)
    conv_501_A7(K32, b'012345678912345', b'\0\0')
    conv_501_A8(K32, 1, 1)
    conv_501_A9(K32, 0, 1)
    conv_501_A10(K32, K32)
    conv_501_A11(K32, 0, 0)
    conv_501_A12(K32, 0, 0)
    conv_501_A13(K32, 1, 0)
    conv_501_A141(K32, 0)
    conv_501_A142(K32, 0)
    conv_501_A151(K32, 0)
    conv_501_A152(K32, K32)
    conv_501_A16(K32, 0)
    conv_501_A17(K32, K16, 0)
    conv_501_A18(K32, 1, 0)
    conv_501_A19(K32, K16, 0)
    conv_501_A20(K32, 1, 0)
    conv_501_A21(K32, 0)
    #conv_501_A22(K32, 0)
    conv_501_A23(K32, K16, K16)
    

# TODO:
# move conversion functions out of the Milenage.py module and put them here
