# −*− coding: UTF−8 −*−

import os
import distutils.ccompiler     as dist_ccomp
import distutils.command.build as dist_build
#
from setuptools                 import setup, Extension
from setuptools.command.install import install


def rename_files(dirpath, fromsuf, tosuf):
    for fn in os.listdir(dirpath):
        if fn.endswith(fromsuf):
            os.rename(dirpath + fn, dirpath + fn[:-len(fromsuf)] + tosuf)

if dist_ccomp.get_default_compiler() == 'msvc':
    # MSVC requires C files to be actually C++ in order to compile them with
    # support for "modern" C features
    print('compiling C extensions with MSVC: renaming .c to .cc')
    rename_files('./C_alg/', '.c', '.cc')
    rename_files('./C_py/', '.c', '.cc')
    pycomp128 = Extension('pycomp128', sources=['C_py/pycomp128.cc', 'C_alg/comp128.cc'])
    pykasumi  = Extension('pykasumi',  sources=['C_py/pykasumi.cc', 'C_alg/Kasumi.cc'])
    pysnow    = Extension('pysnow',    sources=['C_py/pysnow.cc', 'C_alg/SNOW_3G.cc'])
    pyzuc     = Extension('pyzuc',     sources=['C_py/pyzuc.cc', 'C_alg/ZUC.cc'])
    pykeccakp1600 = Extension('pykeccakp1600', sources=['C_py/pykeccakp1600.cc', 'C_alg/KeccakP-1600-3gpp.cc'])
else:
    pycomp128 = Extension('pycomp128', sources=['C_py/pycomp128.c', 'C_alg/comp128.c'])
    pykasumi  = Extension('pykasumi',  sources=['C_py/pykasumi.c', 'C_alg/Kasumi.c'])
    pysnow    = Extension('pysnow',    sources=['C_py/pysnow.c', 'C_alg/SNOW_3G.c'])
    pyzuc     = Extension('pyzuc',     sources=['C_py/pyzuc.c', 'C_alg/ZUC.c'])
    pykeccakp1600 = Extension('pykeccakp1600', sources=['C_py/pykeccakp1600.c', 'C_alg/KeccakP-1600-3gpp.c'])

def postop():
    if dist_ccomp.get_default_compiler() == 'msvc':
        # reverting the renaming
        rename_files('./C_alg/', '.cc', '.c')
        rename_files('./C_py/', '.cc', '.c')

class build_wrapper(dist_build.build):
    def run(self):
        # on windows: rename *.c to *.cc
        # on linux: should run OK
        dist_build.build.run(self)
        postop()

class install_wrapper(install):
    def run(self):
        # on windows: rename *.c to *.cc
        # on linux: should run OK
        install.run(self)
        postop()

setup(
    name='CryptoMobile',
    version='0.3',
    cmdclass={'install': install_wrapper,
              'build'  : build_wrapper},
    packages=['CryptoMobile'],
    ext_modules=[pycomp128, pykasumi, pysnow, pyzuc, pykeccakp1600],
    
    test_suite="test.test_CryptoMobile",
    
    author='Benoit Michau',
    author_email='michau.benoit@gmail.com',
    description='CryptoMobile provides (C)Python bindings to reference implementations '\
                'in C of mobile cryptographic algorithms: Comp128, Milenage, TUAK, Kasumi, SNOW-3G, ZUC',
    long_description=open('README.md', 'r').read(),
    url='https://github.com/P1Sec/CryptoMobile/',
    keywords='cryptography mobile network Kasumi SNOW ZUC Milenage Comp128 TUAK',
    license='GPLv2+',
    )
