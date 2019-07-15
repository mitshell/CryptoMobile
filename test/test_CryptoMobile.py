# -*- coding: UTF-8 -*-
#/**
# * Software Name : CryptoMobile 
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI. P1Sec.
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
from test.test_CM   import test_CM
from test.test_TUAK import test_TUAK


class TestPycrate(unittest.TestCase):
    
    # core objects
    def test_core(self):
        print('[<>] testing CryptoMobile.CM')
        test_CM()
    
    def test_tuak(self):
        print('[<>] testing CryptoMobile.CM.TUAK')
        test_TUAK()

