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
# * File Name : test/test_Milenage.py
# * Created : 2020-01-20
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

from time import time

from CryptoMobile.Milenage import Milenage, make_OPc


OPnull = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


###
# Milenage f1, f1*, f2, f3, f4, f5 and f5*: testsets from 3GPP TS 35.207, section 4, 5 and 6
###

def milenage_testset_1():
    K       = b'F[\\\xe8\xb1\x99\xb4\x9f\xaa_\n.\xe28\xa6\xbc'
    RAND    = b'#U<\xbe\x967\xa8\x9d!\x8a\xe6M\xaeG\xbf5'
    SQN     = b'\xff\x9b\xb4\xd0\xb6\x07'
    AMF     = b'\xb9\xb9'
    OP      = b'\xcd\xc2\x02\xd5\x12> \xf6+mgj\xc7,\xb3\x18'
    #
    return make_OPc(K, OP) == b'\xcdc\xcbq\x95J\x9fNH\xa5\x99N7\xa0+\xaf' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b'J\x9f\xfa\xc3T\xdf\xaf\xb3' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\x01\xcf\xaf\x9e\xc4\xe8q\xe9' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'\xa5B\x11\xd5\xe3\xbaP\xbf',
    b'\xb4\x0b\xa9\xa3\xc5\x8b*\x05\xbb\xf0\xd9\x87\xb2\x1b\xf8\xcb', b'\xf7i\xbc\xd7Q\x04F\x04\x12vrq\x1cm4A', b'\xaah\x9cd\x83p') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'E\x1e\x8b\xec\xa4;'

def milenage_testset_2():
    K       = b'\x03\x96\xeb1{m\x1c6\xf1\x9c\x1c\x84\xcdo\xfd\x16'
    RAND    = b'\xc0\r`1\x03\xdc\xeeR\xc4G\x81\x19IB\x02\xe8'
    SQN     = b'\xfd\x8e\xef@\xdf}'
    AMF     = b'\xaf\x17'
    OP      = b'\xffS\xba\xde\x17\xdf]Ny0s\xce\x9duy\xfa'
    return make_OPc(K, OP) == b'S\xc1Vq\xc6\nKs\x1cU\xb4\xa4A\xc0\xbd\xe2' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b']\xf5\xb3\x18\x07\xe2X\xb0' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\xa8\xc0\x16\xe5\x1e\xf4\xa3C' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'\xd3\xa6(\xed\x98\x86 \xf0',
    b'X\xc43\xffzp\x82\xac\xd4$"\x0f+g\xc5V', b'!\xa8\xc1\xf9)p*\xdb>s\x84\x88\xb9\xf5\xc5\xda', b'\xc4w\x83\x99_r') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'0\xf1\x19pa\xc1'
	
def milenage_testset_3():
    K       = b'\xfe\xc8k\xa6\xebp~\xd0\x89\x05u{\x1b\xb4K\x8f'
    RAND    = b'\x9f|\x8d\x02\x1a\xcc\xf4\xdb!<\xcf\xf0\xc7\xf7\x1aj'
    SQN     = b'\x9d\x02wY_\xfc'
    AMF     = b'r\\'
    OP      = b'\xdb\xc5\x9a\xdc\xb6\xf9\xa0\xefsTw\xb7\xfa\xdf\x83t'
    return make_OPc(K, OP) == b'\x10\x06\x02\x0f\nG\x8b\xf6\xb6\x99\xf1\\\x06.B\xb3' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b'\x9c\xab\xc3\xe9\x9b\xafr\x81' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\x95\x81K\xa2\xb3\x04C$' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'\x80\x11\xc4\x8c\x0c!N\xd2',
    b']\xbd\xbb)T\xe8\xf3\xcd\xe6e\xb0F\x17\x9aP\x98', b'Y\xa9-;Gj\x04CHpU\xcf\x88\xb20{', b'3HM\xc2\x13k') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'\xde\xac\xdd\x84\x8c\xc6'

def milenage_testset_4():
    K       = b'\x9eYD\xae\xa9K\x81\x16\\\x82\xfb\xf9\xf3-\xb7Q'
    RAND    = b"\xce\x83\xdb\xc5J\xc0'J\x15|\x17\xf8\r\x01{\xd6"
    SQN     = b'\x0b`J\x81\xec\xa8'
    AMF     = b'\x9e\t'
    OP      = b'"0\x14\xc5\x80f\x94\xc0\x07\xca\x1e\xee\xf5\x7f\x00O'
    return make_OPc(K, OP) == b'\xa6JPz\xe1\xa2\xa9\x8b\xb8\x8e\xb4!\x015\xdc\x87' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b't\xa5\x82 \xcb\xa8LI' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\xac,\xc7J\x96\x87\x187' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'\xf3e\xcdh<\xd9.\x96',
    b'\xe2\x03\xed\xb3\x97\x15t\xf5\xa9K\ra\xb8\x164]', b'\x0cE$\xad\xea\xc0A\xc4\xdd\x83\r \x85O\xc4k', b'\xf0\xb9\xc0\x8a\xd0.') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'`\x85\xa8loc'

def milenage_testset_5():
    K       = b'J\xb1\xde\xb0\\\xa6\xce\xb0Q\xfc\x98\xe7}\x02j\x84'
    RAND    = b't\xb0\xcd`1\xa1\xc83\x9b+l\xe2\xb8\xc4\xa1\x86'
    SQN     = b'\xe8\x80\xa1\xb5\x80\xb6'
    AMF     = b'\x9f\x07'
    OP      = b'-\x16\xc5\xcd\x1f\xdfk"85\x84\xe3\xbe\xf2\xa8\xd8'
    return make_OPc(K, OP) == b'\xdc\xf0|\xbdQ\x85R\x90\xb9*\x07\xa9\x89\x1eR>' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b'I\xe7\x85\xdd\x12bn\xf2' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\x9e\x85y\x036\xbb?\xa2' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'X`\xfc\x1b\xce5\x1e~',
    b'vWvk7=\x1c!8\xf3\x07\xe3\xde\x92B\xf9', b"\x1cB\xe9`\xd8\x9b\x8f\xa9\x9f'D\xe0p\x8c\xcbS", b'1\xe1\x1a`\x91\x18') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'\xfe%U\xe5J\xa9'

def milenage_testset_6():
    K       = b'l8\xa1\x16\xac(\x0cEOY3.\xe3\\\x8cO'
    RAND    = b'\xeedf\xbc\x96 ,ZUz\xbb\xef\xf8\xba\xbfc'
    SQN     = b'AK\x98"!\x81'
    AMF     = b'Dd'
    OP      = b'\x1b\xa0\n\x1a|g\x00\xac\x8c?\xf3\xe9j\xd0\x87%'
    return make_OPc(K, OP) == b'8\x03\xefSc\xb9G\xc6\xaa\xa2%\xe5\x8f\xae94' and \
    Milenage(OP).f1(K, RAND, SQN, AMF) == Milenage(OPnull).f1(K, RAND, SQN, AMF, OP) == b'\x07\x8a\xdf\xb4\x88$\x1aW' and \
    Milenage(OP).f1star(K, RAND, SQN, AMF) == Milenage(OPnull).f1star(K, RAND, SQN, AMF, OP) == b'\x80$k\x8d\x01\x86\xbc\xf1' and \
    Milenage(OP).f2345(K, RAND) == Milenage(OPnull).f2345(K, RAND, OP) == (b'\x16\xc8#?\x05\xa0\xac(',
    b'?\x8cu\x87\xfe\x8eK#:\xf6v\xae\xde0\xba;', b'\xa7Fl\xc1\xe6\xb2\xa13}I\xd3\xb6n\x95\xd7\xb4', b'E\xb0\xf6\x9a\xb0l') and \
    Milenage(OP).f5star(K, RAND) == Milenage(OPnull).f5star(K, RAND, OP) == b'\x1fS\xcd+\x11\x13'


def milenage_testsets():
    return milenage_testset_1() and milenage_testset_2() and milenage_testset_3() and\
    milenage_testset_4() and milenage_testset_5() and milenage_testset_6()


def testall():
    return milenage_testsets()


def testperf():
    T0 = time()
    for i in range(1000):
        if not testall():
            print('testset failing... exiting')
            return
    print('1000 full Milenage testsets in %.3f seconds' % (time()-T0, ))


def test_Milenage():
    assert( testall() )


if __name__ == '__main__':
    testperf()
