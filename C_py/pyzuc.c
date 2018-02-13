/**
 * Software Name : CryptoMobile 
 * Version : 0.2.0
 *
 * Copyright © 2017. Benoit Michau. ANSSI.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details. 
 *
 * You will find a copy of the terms and conditions of the GNU General Public
 * License version 2 in the "license.txt" file or
 * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 *--------------------------------------------------------
 * File Name : CryptoMobile/pyzuc.c
 * Created : 2017-07-27 
 *--------------------------------------------------------
*/

#include <Python.h>
#include "../C_alg/ZUC.h"


/* Python 2 and 3 initialization mess */


struct module_state {
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3

    #define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))

#else

    #define GETSTATE(m) (&_state)
    static struct module_state _state;

#endif

static PyObject * error_out(PyObject *m) {
    struct module_state *st = GETSTATE(m);
    PyErr_SetString(st->error, "something bad happened");
    return NULL;
}

static PyObject* pyzuc_initialization(PyObject* dummy, PyObject* args);
static PyObject* pyzuc_generatekeystream(PyObject* dummy, PyObject* args);
static PyObject* pyzuc_eea3(PyObject* dummy, PyObject* args);
static PyObject* pyzuc_eia3(PyObject* dummy, PyObject* args);

static char pyzuc_initialization_doc[] =
    "zuc_initialization(key [16 bytes], iv [16 bytes]) -> None";
static char pyzuc_generatekeystream_doc[] =
    "zuc_generatekeystream(n [uint32, number of 32-bit words]) -> keystream [bytes]";
static char pyzuc_eea3_doc[] =
    "zuc_eea3(ck [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
             "length [uint32, length in bits], data_in [bytes]) -> data_out [bytes]";
static char pyzuc_eia3_doc[] =
    "zuc_eia3(ik [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
             "length [uint32, length in bits], data_in [bytes]) -> mac [4 bytes]";

static PyMethodDef pyzuc_methods[] = 
{
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"zuc_initialization", pyzuc_initialization, METH_VARARGS, pyzuc_initialization_doc},
    {"zuc_generatekeystream", pyzuc_generatekeystream, METH_VARARGS, pyzuc_generatekeystream_doc},
    {"zuc_eea3", pyzuc_eea3, METH_VARARGS, pyzuc_eea3_doc},
    {"zuc_eia3", pyzuc_eia3, METH_VARARGS, pyzuc_eia3_doc},
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

    static int pyzuc_traverse(PyObject *m, visitproc visit, void *arg) {
        Py_VISIT(GETSTATE(m)->error);
        return 0;
    }

    static int pyzuc_clear(PyObject *m) {
        Py_CLEAR(GETSTATE(m)->error);
        return 0;
    }

    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT,
            "pyzuc",
            "bindings for ZUC EEA3 and EIA3 LTE cryptographic functions",
            sizeof(struct module_state),
            pyzuc_methods,
            NULL,
            pyzuc_traverse,
            pyzuc_clear,
            NULL
    };

    #define INITERROR return NULL

    PyObject * PyInit_pyzuc(void)

#else

    #define INITERROR return

    void initpyzuc(void)

#endif

{
    #if PY_MAJOR_VERSION >= 3
    
        PyObject *module = PyModule_Create(&moduledef);
    
    #else
    
        PyObject *module = Py_InitModule4(
            "pyzuc",
            pyzuc_methods,
            "bindings for ZUC EEA3 and EIA3 LTE cryptographic functions",
            0,
            PYTHON_API_VERSION);
    
    #endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("pyzuc.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    #if PY_MAJOR_VERSION >= 3
    
        return module;
    
    #endif
}


/* pyzuc binding to ZUC.h */


// utiliy macro and function required for handling (char *) to (u32 *) conversion

#define SWAP_BYTES(X) \
  ((((X) & 0xff000000) >> 24) | (((X) & 0x00ff0000) >>  8) | \
   (((X) & 0x0000ff00) <<  8) | (((X) & 0x000000ff) << 24))


void memcpy_bswap(u32* bufout, char* bufin, u32 n)
{
    u32 i;
    
    // copy bufin into bufout
    memcpy(bufout, bufin, 4*n);
    
    // swap bytes of uint32_t values within bufout
    for (i=0; i<n; i++)
        bufout[i] = SWAP_BYTES(bufout[i]);
};


static PyObject* pyzuc_initialization(PyObject* dummy, PyObject* args)
{
    // input: key, IV (bytes buffer -> u8 *)
    Py_buffer k;
    Py_buffer iv;
    
    if (! PyArg_ParseTuple(args, "z*z*", &k, &iv))
        return NULL;
    
    if ((k.len != 16) || (iv.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    //void Initialization(u8* k, u8* iv);
    Initialization((u8 *)k.buf, (u8 *)iv.buf);
    
    Py_RETURN_NONE;
};


static PyObject* pyzuc_generatekeystream(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    u32 i;
    
    // input: n (int -> u32, number of bits of keystream)
    u32 KeystreamLen;
    u32 * pKeystream;
    
    if (! PyArg_ParseTuple(args, "I", &KeystreamLen))
        return NULL;
    
    // output: pKeystream (u32 * -> bytes buffer)
    pKeystream = (u32 *)malloc(4*KeystreamLen);
    if (pKeystream == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    
    //GenerateKeystream(u32* pKeystream, u32 KeystreamLen);
    GenerateKeystream(pKeystream, KeystreamLen);
    
    // swap u32 bytes on place for pKeystream
    for (i=0; i<KeystreamLen; i++)
        pKeystream[i] = SWAP_BYTES(pKeystream[i]);
    
    ret = PyBytes_FromStringAndSize((char *)pKeystream, 4*KeystreamLen);
    free(pKeystream);
    pKeystream = NULL;
    
    return ret;
};


static PyObject* pyzuc_eea3(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: CK (bytes buffer -> u8 *), COUNT, BEARER, DIRECTION, LENGTH (int -> u32),
    //        M (bytes buffer -> u32 *)
    Py_buffer CK;
    Py_buffer M_py;
    u32 COUNT, BEARER, DIRECTION, LENGTH, out_wsz, i;
    int out_sz;
    u32 * M;
    u32 * C;
    
    if (! PyArg_ParseTuple(args, "z*IIIIz*", &CK, &COUNT, &BEARER, &DIRECTION, &LENGTH, &M_py))
        return NULL;
    
    // transform length in bits to length in bytes
    out_sz = LENGTH >> 3;
    if (LENGTH % 8)
        out_sz++;
    
    // transform length in bits to length in 32-bits words
    out_wsz = LENGTH >> 5;
    if (LENGTH % 32)
        out_wsz++;
    
    if ((CK.len != 16) || (DIRECTION > 1) || (out_sz > M_py.len))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    // swap u32 bytes from Python buffer M_py into new array M
    M = (u32 *)malloc(4*out_wsz);
    if (M == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    memcpy_bswap(M, (char *)M_py.buf, out_wsz);
    
    // output: C (u32 * -> bytes buffer of size length in bits)
    C = (u32 *)malloc(out_wsz<<2);
    if (C == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    
    //void void EEA3(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* C);
    EEA3((u8 *)CK.buf, COUNT, BEARER, DIRECTION, LENGTH, M, C);
    free(M);
    M = NULL;
    
    // swap u32 bytes on place for C
    for (i=0; i<out_wsz; i++)
        C[i] = SWAP_BYTES(C[i]);
    
    ret = PyBytes_FromStringAndSize((char *)C, out_sz);
    free(C);
    C = NULL;
    
    return ret;
};


static PyObject* pyzuc_eia3(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: IK (bytes buffer -> u8 *), COUNT, BEARER, DIRECTION, LENGTH (int -> u32),
    //        M (bytes buffer -> u32 *)
    Py_buffer IK;
    Py_buffer M_py;
    u32 COUNT, BEARER, DIRECTION, LENGTH, m_wsz;
    int m_sz;
    u32 * M;
    // output: MAC (u32 * -> bytes buffer of size 4)
    u32 MAC[1];
    
    if (! PyArg_ParseTuple(args, "z*IIIIz*", &IK, &COUNT, &BEARER, &DIRECTION, &LENGTH, &M_py))
        return NULL;
    
    // transform length in bits to length in bytes
    m_sz = LENGTH >> 3;
    if (LENGTH % 8)
        m_sz++;
    
    // transform length in bits to length in 32-bits words
    m_wsz = LENGTH >> 5;
    if (LENGTH % 32)
        m_wsz++;
    
    if ((IK.len != 16) || (DIRECTION > 1) || (m_sz > M_py.len))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    // swap u32 bytes from Python buffer M_py into new array M
    M = (u32 *)malloc(4*m_wsz);
    if (M == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    memcpy_bswap(M, (char *)M_py.buf, m_wsz);
    
    //void EIA3(u8* IK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* MAC);
    EIA3((u8 *)IK.buf, COUNT, BEARER, DIRECTION, LENGTH, M, MAC);
    free(M);
    M = NULL;
    
    // swap bytes of the MAC on place
    *MAC = SWAP_BYTES(*MAC);
    
    ret = PyBytes_FromStringAndSize((char *)MAC, 4);
    return ret;
};
