# -*- coding: UTF-8 -*-
#/**
# * Software Name : CryptoMobile 
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI.
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : test/test_CryptoMobile.py
# * Created : 2018-02-09
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import unittest

from test.test_CM       import (
    test_CM,
    testperf as testperf_CM
    )
from test.test_TUAK     import (
    test_TUAK,
    testperf as testperf_TUAK
    )
try:
    from test.test_Milenage import (
        test_Milenage,
        testperf as testperf_Milenage
        )
except ImportError:
    _with_aes = False
else:
    _with_aes = True
    try:
        from test.test_ECIES    import (
            test_ECIES,
            testperf as testperf_ECIES
            )
    except ImportError:
        _with_ec = False
    else:
        _with_ec = True


class TestCryptoMobile(unittest.TestCase):
    
    # core objects
    def test_core(self):
        print('[<>] testing CryptoMobile.CM')
        test_CM()
    
    def test_tuak(self):
        print('[<>] testing CryptoMobile.TUAK')
        test_TUAK()
    
    if _with_aes:
        
        def test_milenage(self):
            print('[<>] testing CryptoMobile.Milenage')
            test_Milenage()
        
        if _with_ec:
            
            def test_ecies(self):
                print('[<>] testing CryptoMobile.ECIES')
                test_ECIES()


if __name__ == '__main__':
    testperf_CM()
    testperf_TUAK()
    if _with_aes:
        testperf_Milenage()
        if _with_ec:
            testperf_ECIES()
