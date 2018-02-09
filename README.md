# CryptoMobile toolkit

## About
This toolkit implements python wrappers around 3G and LTE encryption and 
integrity protection algorithms, COMP128 and Milenage authentication algorithms.

## Disclaimer
This is delivered for study only: beware that cryptographic material, 
especially ciphering algorithms are always subject to national regulation.
Moreover, use in real networks and equipments of some of the algorithms provided
are subect to agreement / licensing by the GSMA and / or the ETSI:
see [GSMA](https://www.gsma.com/aboutus/leadership/committees-and-groups/working-groups/fraud-security-group/security-algorithms)
and [ETSI](http://www.etsi.org/about/what-we-do/security-algorithms-and-codes/cellular-algorithm-licences).

## Installation
The standard installation process is to use the CPython build environment to compile
C files and install them together with the Python wrappers. The Milenage and EEA2/EIA2
algorithms moreover require the [Pycrypto](https://github.com/dlitz/pycrypto) library 
for supporting AES.

An installation script is available.
It installs the library within your Python package directory:

```
python setup.py install
```

It is also possible to test the library before installing it:

```
python setup.py test
```

Or to simply build the library without installing it in the system:

```
python setup.py build
```

For generic info on building C extensions on Windows, see the 
[Python wiki](https://wiki.python.org/moin/WindowsCompilers).
When building on a Windows system using the MSVC compiler, the .c files will be
renamed to .cc by the install script in order to get it compiled correctly by the
MSVC compiler.

### Installing the ctypes version instead of the CPython wrappers
There is still the possibility to install by hand the previous version using Python-only
_ctypes_ source files. A *CM_ctypes.py* is available in the _ctypes directory.
    
TODO

## Usage
Most of the classes and methods have docstrings. Just read them to get information
on how to use and call them.

### CMAC mode of operation
TODO

### COMP128
TODO

### Milenage
TODO

### UMTS encryption and integrity protection algorithms
TODO

### LTE encryption and integrity protection algorithms
TODO

### The CM module, with an example of SNOW 3G operation
```
>>> from CryptoMobile.CM import *
>>> dir()
['AES_3GPP', 'EEA1', 'EEA2', 'EEA3', 'EIA1', 'EIA2', 'EIA3', 'KASUMI', 'SNOW3G', 'UEA1', 'UEA2', 'UIA1', 'UIA2', 'ZUC', '__builtins__', '__doc__', '__name__', '__package__']
>>> UIA2(key=16*b'\xab', count=0x1234, fresh=0x986532ab, dir=0, data=100*b'nepascourirauborddelapiscine')
b':\xe5t:'
>>> UEA2(key=16*b'\xab', count=0x1234, bearer=0x8, dir=0, data=100*b'nepascourirauborddelapiscine')
b'\x03Z\xa0\x83\x14\x198l\x1b\x91\\\x94\x18\xfc\xbd\xecb-\xdfs1\xd6\xbb1\x88y\xf0\xc9\xf5\xec\xc5\x1b\x7f\xcc...'
>>> UEA2(key=16*b'\xab', count=0x1234, bearer=0x8, dir=0, data=_)
b'nepascourirauborddelapiscinenepascourirauborddelapiscinenepascourirauborddelapiscinenepascourirauborddelapi...'

>>> help(EEA2)
Help on method EEA2 in module CryptoMobile.CM:
EEA2(self, key=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', count=0, bearer=0, dir=0, data=b'', bitlen=None) method of CryptoMobile.CM.AES_3GPP instance

>>> EEA2(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=50*b'MonPantalonS\'EstDecousu', bitlen=1149)
b'-y\xf1\xee\xb7\xe4\x0c\xf2\xdfz`\xb04"\x8c\xda\xc8B!n\x863V"\xaei\x91\x1b\xc5\xfc\x1dx\xb9l\xe8\x99q\\q\x88\x91\xc8f\r\x05\xdf\x94S\x97\xc0\x96\xb75\x00@\...'
>>> EEA2(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=_, bitlen=1149)
b"MonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPah"
>>> EIA3(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=50*'MonPantalonS\'EstDecousu', bitlen=1149)
b'\xa9\xc5h\x9e'
```

### running UMTS and LTE algorithms test vectors
By running the setup test (see installation), test vectors will all be run.
You can also run some performance test by hand:

```
$ python test/test_CM.py
1000 full testsets in 25.970 seconds
```

## Content
The library is structured into 3 main parts:
- C_alg: provides C source codes for comp128, Kasumi, SNOW 3G and ZUC
- C_py: provides C source files wrapping those algorithms with CPython (for both 
  Python2 and Python3)
- CryptoMobile: provides Python source files.
- test: provides files with test vectors.
- _ctypes: provides the old CM module which uses ctypes binding to the C files
  compiled as shared object.

Within the CryptoMobile directory, we have to following modules:
- utils.py: provides common routine (eg log() and exception) for the library
- CMAC.py: provides a CMAC class which implement the CMAC mode of operation
- CM.py: the main module providing classes KASUMI, SNOW3G, ZUC (making use of the
  wrappers in C_py) and AES_3GPP (making use of the pycrypto AES implementation),
  and functions UEA1, UIA1, UEA2, UIA2, EEA1, EIA1, EEA2, EIA2, EEA3 and EIA3. 
- Milenage.py: provides the Milenage algorithm and conversion functions to be used
  for keys and authentication vectors conversion.

## Credits
- ETSI / SAGE for providing public cryptographic specifications, together with
  reference C source code
- FreeRADIUS, Hacking projects, Sylvain Munaut, for the comp128.c source code
