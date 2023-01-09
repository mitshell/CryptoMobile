# CryptoMobile toolkit

## Update 2019
The fork at [P1sec](https://github.com/P1sec/CryptoMobile) is going to be more actively maintained and extended than this project.
Do not hesitate to clone it instead of this one.


## About
This toolkit implements python wrappers around 3G and LTE encryption and 
integrity protection algorithms, COMP128, Milenage and TUAK authentication 
algorithms, and ECIES identity protection scheme.


## Disclaimer
This is delivered for study only: beware that cryptographic material, 
especially ciphering algorithms are always subject to national regulation.
Moreover, use in real networks and equipments of some of the algorithms provided
are subect to agreement / licensing by the GSMA and / or the ETSI:
see [GSMA](https://www.gsma.com/aboutus/leadership/committees-and-groups/working-groups/fraud-security-group/security-algorithms)
and [ETSI](https://www.etsi.org/security-algorithms-and-codes/security-algorithms).


## Installation
The standard installation process is to use the CPython build environment to compile
C files and install them together with the Python wrappers. The Milenage and EEA2/EIA2
algorithms moreover require one of the following Python cryptographic library to support
AES:
- [pycryptodome](https://www.pycryptodome.org/en/latest/src/installation.html) or
- [cryptography](https://cryptography.io/en/latest/)

The ECIES module require the last one (cryptography) to work, as no support for ECIES 
with pycryptodome as been developped yet.


This library supports both Python 2.7 and 3 versions.
An installation script is available: it installs the library within your Python 
package directory:

```
python setup.py install
```
or to make a system-wide install
```
sudo python setup.py install
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
When building on a Windows system using the MSVC compiler, the .c files will be automatically
renamed to .cc by the install script in order to get them compiled correctly by the MSVC compiler.

To be noted also that the library builds and runs fine with pypy3.


### Installing the ctypes version instead of the CPython wrappers
There is still the possibility to install manually the historical version (before 2019) 
of the library which uses Python-only _ctypes_ source files. A *CM_ctypes.py* is available 
in the \_ctypes directory for this purpose.
Please note that this part is not supported anymore, no more tested, and may not work correctly
or even at all.


## Usage
Most of the classes and methods have docstrings. Just read them to get information
on how to use and call them.


Warning: most of the C reference implementations are using global or static variables,
which are making them not thread-safe. Using them through Python is however OK thanks 
to the GIL, but beware in case you want to use them directly from C.


### CMAC mode of operation
This is the CBC-MAC mode as defined by NIST. It works with any block cipher primitive,
and returns MAC of any length in bits. This is written in pure Python.

Here is an example on how to use it with AES:
```
>>> from CryptoMobile.CMAC import CMAC
>>> help(CMAC)
[...]
>>> from CryptoMobile.AES import AES_ECB
>>> key = 16*b'A'
>>> cmac = CMAC(key, AES_ECB, Tlen=48)
>>> cmac.cmac(200*b'test')
b'\xf7\xad\x89-j\n'
>>> cmac.cmac(200*b'test', (200*8)-2) # this is to not compute the MAC over the last 2 bits of the input
b'\xa7\x7f\xc4\xbf\xfc\xf4'
```

### COMP128
This is the Python wrapper over the COMP128 v1, v2 and v3 algorithms. The C code
has been taken from the FreeRADIUS project.

Here is an example on how to use it:
```
>>> from pycomp128 import *
>>> help(comp128v1)
[...]
>>> key, rand = 16*b'A', 16*b'B'
>>> comp128v1(key, rand)
(b'#9\x0b^', b"\x08\xb6'\xf36\x80\xec\x00")
>>> comp128v2(key, rand)
(b'\x8a\x9b\xaaI', b']\xdcPs\xa6:\x04\x00')
>>> comp128v3(key, rand)
(b'\x8a\x9b\xaaI', b']\xdcPs\xa6:\x07\xf9')
```

### Milenage
This is Python wrapper over the Milenage algorithm. The mode of operation is written
in Python, and makes use of the AES function from one of the AES Python backend found.

c1 to c5 and r1 to r5 constants are implemented as class attribute.
The class must be instantiated with the OP parameter.

Here is an example on how to use it:
```
>>> from CryptoMobile.Milenage import Milenage
>>> help(Milenage)
[...]
>>> Milenage.c1
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> Milenage.c2
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
>>> Milenage.r3
32
>>> OP = 16*b'F'
>>> Mil = Milenage(OP)
>>> key, rand = 16*b'A', 16*b'B'
>>> help(Mil.f1)
[...]
>>> Mil.f1(key, rand, SQN=b'\0\0\0\0\x12\x34', AMF=b'\0\0')
b'\x18\x92\x97\xa2\xbb\x08i\xf0'
>>> Mil.f1(key, rand, SQN=b'\0\0\0\0\x12\x34', AMF=b'\0\0', OP=16*b'G') # it is possible the use a different OP parameter
b'E\xf0\xb4\xef\x0c\xa6\x95\xe1'
>>> help(Mil.f2345)
[...]
>>> Mil.f2345(key, rand)
(b'\xdd\x0b\x0f\x95\x92\x06\x1e\xb9', b'~\x8d\xf5&\xe37\xc2\xaf\xe4\x83\xc5\x802\xf7\x1fV', b'\x82;\xcfM\xc5\xfc{\x06BM\xd1\xd6UZJ\xa2', b'g\xe8\x85\r\x0b\xd9')
```

The defaut behaviour is to recompute the OPc at each method call. In order to save
some AES rounds in case you want to compute several authentication vectors for a given
subscriber, it is possible to set the OPc before calling the f methods.
```
>>> help(Mil.make_opc)
[...]
>>> from CryptoMobile.Milenage import make_OPc
>>> Mil.set_opc(make_OPc(key, OP))
>>> Mil.f1(key, rand, SQN=b'\0\0\0\0\x12\x35', AMF=b'\0\0')
b'\xf7~|\x95\x9e\xbf\xfb?'
>>> Mil.f2345(key, rand)
(b'\xdd\x0b\x0f\x95\x92\x06\x1e\xb9', b'~\x8d\xf5&\xe37\xc2\xaf\xe4\x83\xc5\x802\xf7\x1fV', b'\x82;\xcfM\xc5\xfc{\x06BM\xd1\xd6UZJ\xa2', b'g\xe8\x85\r\x0b\xd9')
>>> Mil.unset_opc()
```

Some conversion functions are also provided in the Milenage module:
- conv\_C2, conv\_C3, conv\_C4 and conv\_C5 for 2G / 3G authentication vectors conversion
- conv\_A2, conv\_A3, conv\_A4 and conv\_A7 for LTE key derivation and 3G / LTE authentication 
   vectors conversion


### TUAK
This is the Python wrapper over the TUAK algorithm. The mode of operation is written
in Python, and makes use of the KeccakP-1600 permutation function. The C code for this
permutation function has been taken from the 3GPP TS 35.231 specification.

TUAK algorithm is to be used similarly as Milenage. TOP (TUAK-OP) is replacing OP
and TOPc is replacing OPc. TOP, TOPc are 32 bytes, secret keys K can be 16 or 32 bytes.
Length of outputs produced (MAC, RES, CK and IK) can be configured through the following
class attributes too: LEN\_CK, LEN\_IK, LEN\_MAC, LEN\_RES.
Moreover, the algorithm can be personalized with 2 parameters, implemented as class 
attributes: ALGONAME and KeccakIterations. On the other side, there is no such constants 
as c1..c5 and r1..r5, as in Milenage.

Here is an example on how to use it:
```
>>> from CryptoMobile.TUAK import TUAK
>>> help(TUAK)
[...]
>>> TUAK.ALGONAME
b'TUAK1.0'
>>> TUAK.KeccakIterations
1
>>> TOP = 32*b'F'
>>> Tuak = TUAK(TOP)
>>> key, rand = 32*b'A', 16*b'B'
>>> help(Tuak.f1)
[...]
>>> Tuak.f1(key, rand, SQN=b'\0\0\0\0\x12\x34', AMF=b'\x80\0')
b'\xdd\xf1\xc7w\x11x\xce\xdb'
>>> Tuak.f2345(key, rand)
(b'}/\xdc\xd4\xcb(qG', b'\xa8\x1dF\x84\x80\xac\t\xab\xe4\xa3\xf6\xe1\x8b\x9b7\xfe', b'g~=\xaf1\xfcy\x9b\x92\xc6\xd2M\xfa\xd0\xed\t', b'\x83\x1e\xcbp\xa6"')
```

TOPc handling is similar as in Milenage and can be set explicitly through the set\_topc() method
before calling f1() and f2345() methods several times, then finally unset with unset\_topc() method.
 

### Kasumi-based encryption and integrity protection algorithms
This is a Python wrapper around the reference C code of Kasumi and its mode of operation
for 3G networks. Kasumi is a block cipher working with 64 bit blocks.

Here is an example on how to use the Kasumi primitive:
```
>>> from pykasumi import *
>>> help(kasumi_keyschedule)
[...]
>>> help(kasumi_kasumi)
[...]
>>> key, block_in = 16*b'A', 8*b'B'
>>> kasumi_keyschedule(key)
>>> kasumi_kasumi(block_in)
b"S\xf6']\x1c\x1e\xfd\x00"
```

And the Kasumi in F8 and F9 modes of operation:
```
>>> help(kasumi_f8)
[...]
>>> help(kasumi_f9)
[...]
>>> key, count, bearer, dir = 16*b'A', 107, 3, 0
>>> kasumi_f8(key, count, bearer, dir, 10*b'test', 10*4*8)
b'q\xe9\x86\xdd\xde\xc1\x14\xb0=pv2|\xe8\\Ib\x84\xa1\xf9\xc0\x01=)\xac!mV\xe4\xc15L\t\xf0\x1f\x1b\x02\xb8\xf9l'
>>> kasumi_f9(key, count, bearer, dir, 10*b'test', 10*4*8)
b'\x1c!j\x0e'
```

### SNOW-3G-based encryption and integrity protection algorithms
This is a Python wrapper around the reference C code of SNOW-3G and its mode of operation
for 3G and LTE networks. SNOW-3G is a stream cipher working with 32 bit words.

Here is an example on how to use the SNOW-3G primitive:
```
>>> from pysnow import *
>>> help(snow_initialize)
[...]
>>> help(snow_generatekeystream)
[...]
>>> key, iv = 16*b'A', 16*b'B'
>>> snow_initialize(key, iv)
>>> snow_generatekeystream(6)
b'\\^\xff\x98\xad\xa6\x17\xb8\xa4e\x03S\x93T\xbew\xc7\xd1gpr\xf3\x99\xd9'
```

And the SNOW-3G in F8 and F9 modes of operation:
```
>>> help(snow_f8)
[...]
>>> help(snow_f9)
[...]
>>> key, count, bearer, dir = 16*b'A', 107, 3, 0
>>> snow_f8(key, count, bearer, dir, 10*b'test', 10*4*8)
b'{\x98\xa1\x90\x0c\x9f\xe9zNp3\xba\xdc\xa6|-\xfe\x91\xffk\x99\x9d\xbc^\xc3\xe1n\xbd\x06U\x98\xfa\x82 \x1a\xf2\xf6\x08\xbb\xe7'
>>> snow_f9(key, count, bearer, dir, 10*b'test', 10*4*8)
b'\xe0\x8e\xde\x85'
```

The EEA1-128 and EIA1-128 modes of operation for LTE are similar to F8 and F9 for 3G
networks.


### ZUC-based encryption and integrity protection algorithms
This is a Python wrapper around the reference C code of ZUC and its mode of operation
for LTE networks. ZUC is a stream cipher working with 32 bit words.

Here is an example on how to use the ZUC primitive:
```
>>> from pyzuc import *
>>> help(zuc_initialization)
[...]
>>> help(zuc_generatekeystream)
[...]
>>> key, iv = 16*b'A', 16*b'B'
>>> zuc_initialization(key, iv)
>>> zuc_generatekeystream(4)
b'\xcf{\x10P\x1e\xf3c\x13\x1c}\x0c\xc2\x8c\xd8\x1a\xae'
```

And the ZUC in EEA3 and EIA3 modes of operation:
```
>>> help(zuc_eea3)
[...]
>>> help(zuc_eia3)
[...]
>>> key, count, bearer, dir = 16*b'A', 107, 3, 0
>>> zuc_eea3(key, count, bearer, dir, 10*4*8, 10*b'test')
b'\xda\x9as,\x97:\x86)]\xde\x8b\x14Qq\x85\x15cME$\xc4)\xe7\x7f@\xfe\x10\x1f\xcd\xb05G\xa0\x1d9\x92\x85L2 '
>>> zuc_eia3(key, count, bearer, dir, 10*4*8, 10*b'test')
b'X\xcb\xa1\x9c'
```

### The CM module, gathering all 3G and LTE encryption and integrity protection algorithms in one place
The CM module implements each algorithm as a class, with its primitives and 3G and / or LTE
modes of operation as specific methods.
Finally, UEA and UIA are aliases for the given UMTS encryption and integrity protection
algorithms, and EEA and EIA are aliases for the given LTE encryption and integrity
protection algorithms.

Here is an example with the 2nd UMTS algorithm (SNOW-3G based) and the 2nd and 3rd 
LTE algorithms (AES-based and ZUC-based):
```
>>> from CryptoMobile.CM import *
>>> dir()
['AES_3GPP', 'EEA1', 'EEA2', 'EEA3', 'EIA1', 'EIA2', 'EIA3', 'KASUMI', 'SNOW3G', 'UEA1', 'UEA2', 'UIA1', 'UIA2', 'ZUC', '__builtins__', '__doc__', '__name__', '__package__']
>>> help(UIA2)
[...]
>>> UIA2(key=16*b'\xab', count=0x1234, fresh=0x986532ab, dir=0, data=100*b'nepascourirauborddelapiscine')
b':\xe5t:'
>>> help(UEA2)
[...]
>>> UEA2(key=16*b'\xab', count=0x1234, bearer=0x8, dir=0, data=100*b'nepascourirauborddelapiscine')
b'\x03Z\xa0\x83\x14\x198l\x1b\x91\\\x94\x18\xfc\xbd\xecb-\xdfs1\xd6\xbb1\x88y\xf0\xc9\xf5\xec\xc5\x1b\x7f\xcc...'
>>> UEA2(key=16*b'\xab', count=0x1234, bearer=0x8, dir=0, data=_)
b'nepascourirauborddelapiscinenepascourirauborddelapiscinenepascourirauborddelapiscinenepascourirauborddelapi...'

>>> help(EEA2)
[...]
>>> EEA2(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=50*b'MonPantalonS\'EstDecousu', bitlen=1149)
b'-y\xf1\xee\xb7\xe4\x0c\xf2\xdfz`\xb04"\x8c\xda\xc8B!n\x863V"\xaei\x91\x1b\xc5\xfc\x1dx\xb9l\xe8\x99q\\q\x88\x91\xc8f\r\x05\xdf\x94S\x97\xc0\x96\xb75\x00@\...'
>>> EEA2(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=_, bitlen=1149)
b"MonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPantalonS'EstDecousuMonPah"
>>> help(EIA3)
[...]
>>> EIA3(key=16*b'\xc1', count=0x9955ab, bearer=0x16, dir=1, data=50*'MonPantalonS\'EstDecousu', bitlen=1149)
b'\xa9\xc5h\x9e'
```


### ECIES module to support 5G SUPI / SUCI protection scheme
The ECIES module, which relies on the python cryptography library, supports both
ECIES profiles A and B, as described in 3GPP TS 33.501, annex C.

At first a fixed Home-Network public / private keypair needs to be established. For this,
the module EC can be used:
```
>>> from CryptoMobile.EC import *
>>> ec = X25519() # using Curve25519 elliptic curve, i.e. profile A
>>> ec.generate_keypair()
>>> hn_pubkey = ec.get_pubkey()
>>> hn_pubkey
b"\xd9-\x98\xc5\x08\xa7M\x18\x80bi\x0b\xfa-\xd6[D\xe9'\xe4G|\x1d\xe1sRjXM[\xc7;"
>>> hn_privkey = ec.get_privkey()
>>> hn_privkey
b'`y\x06o\xcf\x9c\xe0\xa4\x18\xb1ks\xe6\x97\xafB)\xeftt2\xcfX\xe4\x82\xaf/\x83[\xcc\xa7O'
>>> ec = ECDH_SECP256R1() # using secp256r1 elliptic curve domain, i.e. profile B
>>> ec.generate_keypair()
>>> hn_pubkey = ec.get_pubkey()
>>> hn_pubkey
b'\x03u\xe82C\xa3.\x0e)\xaf\xd6\xad\n\x01\xafZ2\xca\xc9\x95G\\xG\x9d\xdczU\x91n\x1d%m'
>>> hn_privkey = ec.get_privkey()
>>> hn_privkey # the private key for secp256r1 is longer as it is actually packed into a DER-encoded PKCS8 structure
b"0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=[...]\x86'\x17"
```

In the principle, the public key of the home network needs to be setup in subscribers' SIM card, whereas
the private key needs to be securely stored within the home network. Take care as the current version
of the EC module does not provide options to manage those generated private keys password-protected when
exported / imported.

Then, when a subscriber wants to encrypt its fixed identity (e.g. the MSIN part of its IMSI), 
to be then decrypted within the home network:
```
>>> ue_msin = b'\x102Tv\x98' # BCD-encoded value of the digit-string 0123456789
>>> from CryptoMobile.ECIES import *
>>> ue = ECIES_UE(profile='A')
>>> ue.generate_sharedkey(hn_pubkey)
>>> ue_pubkey, ue_ciphertext, ue_mac = ue.protect(ue_msin)
>>> ue_pubkey, ue_ciphertext, ue_mac
(b'\xe1\x1dBR\x8e\xcbd\x05\x94J\xf2ka\xee^\xaa\x96`\x87X\xe3\x96R\xd8w\xcb\xda\x0e}\xab\x9f\x01',
 b'\x93I\x95?8',
 b'\xbc\x91\xe1\x0cy\xe2\xf5\xa6')
>>> hn = ECIES_HN(hn_privkey, profile='A')
>>> hn_msin = hn.unprotect(ue_pubkey, ue_ciphertext, ue_mac)
>>> hn_msin == ue_msin
True
```


### running Milenage, TUAK, ECIES, UMTS and LTE algorithms test vectors
By running the setup test (see installation), test vectors will all be run.
You can also run some performance test by hand:

```
$ python test/test_CM.py
1000 full testsets in 7.393 seconds
$ python test/test_Milenage.py
1000 full testsets in 1.494 seconds
$ python test/test_TUAK.py
10000 full testsets in 2.215 seconds
$ python test/test_ECIES.py
1000 full testsets in 2.202 seconds
```


## Content
The library is structured into 3 main parts:
- C\_alg: provides C source codes for comp128, KeccakP-1600, Kasumi, SNOW 3G and ZUC
- C\_py: provides C source files wrapping those algorithms with CPython (for both 
  Python2 and Python3)
- CryptoMobile: provides Python source files.

And two additional folders:
- test: provides files with test vectors.
- \_ctypes: provides the old CM module which uses ctypes binding to the C files
  compiled as shared object.

Within the CryptoMobile directory, we have the following modules:
- utils.py: provides common routine (eg log() and exception) for the library
- AES.py: provides support for several AES Python backend
- CMAC.py: provides a CMAC class which implement the CMAC mode of operation
- CM.py: the main module providing classes KASUMI, SNOW3G, ZUC (making use of the
  wrappers in C\_py) and AES\_3GPP (making use of the AES backend),
  and functions UEA1, UIA1, UEA2, UIA2, EEA1, EIA1, EEA2, EIA2, EEA3 and EIA3. 
- Milenage.py: provides the Milenage algorithm and conversion functions to be used
  for keys and authentication vectors conversion.
- TUAK.py: provides the TUAK algorithm.
- EC.py: provides both Curve25519 and secp256r1 elliptic curve modules for key exchange
- ECIES.py: provides ECIES processing for 5G SUPI / SUCI protection scheme


## Credits
- ETSI / SAGE for providing public cryptographic specifications, together with
  reference C source code
- FreeRADIUS, Hacking projects, Sylvain Munaut, for the comp128.c source code
- Developers and maintainers of pycrypto, pycryptodome and cryptography Python libraries 

