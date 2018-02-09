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
 * File Name : CryptoMobile/pysnow.c
 * Created : 2017-07-27 
 *--------------------------------------------------------
*/

#include <Python.h>
#include "../C_alg/SNOW_3G.h"


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

static PyObject* pysnow_initialize(PyObject* dummy, PyObject* args);
static PyObject* pysnow_generatekeystream(PyObject* dummy, PyObject* args);
static PyObject* pysnow_f8(PyObject* dummy, PyObject* args);
static PyObject* pysnow_f9(PyObject* dummy, PyObject* args);

static char pysnow_initialize_doc[] =
    "snow_initialize(key [16 bytes], iv [16 bytes]) -> None";
static char pysnow_generatekeystream_doc[] =
    "snow_generatekeystream(n [uint32, number of 32-bit words]) -> keystream [bytes]";
static char pysnow_f8_doc[] =
    "snow_f8(ck [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
            "data_in [bytes], length [uint32, length in bits]) -> data_out [bytes]";
static char pysnow_f9_doc[] =
    "snow_f9(ik [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
            "data_in [bytes], length [uint32, length in bits]) -> mac [4 bytes]";

static PyMethodDef pysnow_methods[] = 
{
    //{exported name, function, args handling, doc string}
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"snow_initialize", pysnow_initialize, METH_VARARGS, pysnow_initialize_doc},
    {"snow_generatekeystream", pysnow_generatekeystream, METH_VARARGS, pysnow_generatekeystream_doc},
    {"snow_f8", pysnow_f8, METH_VARARGS, pysnow_f8_doc},
    {"snow_f9", pysnow_f9, METH_VARARGS, pysnow_f9_doc},
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

    static int pysnow_traverse(PyObject *m, visitproc visit, void *arg) {
        Py_VISIT(GETSTATE(m)->error);
        return 0;
    }

    static int pysnow_clear(PyObject *m) {
        Py_CLEAR(GETSTATE(m)->error);
        return 0;
    }

    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT,
            "pysnow",
            "bindings for SNOW-3G F8 and F9 UMTS cryptographic functions",
            sizeof(struct module_state),
            pysnow_methods,
            NULL,
            pysnow_traverse,
            pysnow_clear,
            NULL
    };

    #define INITERROR return NULL

    PyObject * PyInit_pysnow(void)

#else

    #define INITERROR return

    void initpysnow(void)

#endif

{
    #if PY_MAJOR_VERSION >= 3
    
        PyObject *module = PyModule_Create(&moduledef);
    
    #else
    
        PyObject *module = Py_InitModule4(
            "pysnow",
            pysnow_methods,
            "bindings for SNOW-3G F8 and F9 UMTS cryptographic functions",
            0,
            PYTHON_API_VERSION);
    
    #endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("pysnow.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    #if PY_MAJOR_VERSION >= 3
    
        return module;
    
    #endif
}


/* pysnow binding to SNOW_3G.h */


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


static PyObject* pysnow_initialize(PyObject* dummy, PyObject* args)
{
    // input: key, IV (bytes buffer -> u8 *)
    Py_buffer k_py;
    Py_buffer IV_py;
    u32 k[4];
    u32 IV[4];
    
    if (! PyArg_ParseTuple(args, "z*z*", &k_py, &IV_py))
        return NULL;
    
    if ((k_py.len != 16) || (IV_py.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    // swap u32 bytes from Python buffer into new array
    memcpy_bswap(k, (char *)k_py.buf, 4);
    memcpy_bswap(IV, (char *)IV_py.buf, 4);
    
    //void Initialize(u32 k[4], u32 IV[4]);
    Initialize(k, IV);
    
    Py_RETURN_NONE;
};


static PyObject* pysnow_generatekeystream(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    u32 i;
    
    // input: n (int -> u32, number of 32-bits words of keystream)
    u32 n;
    // output: z (u32 * -> bytes buffer, keystream)
    u32 * z;
    
    if (! PyArg_ParseTuple(args, "I", &n))
        return NULL;
    
    z = (u32 *)malloc(4*n);
    if (z == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    
    //void GenerateKeystream(u32 n, u32 *z);
    GenerateKeystream(n, z);
    
    // swap u32 bytes on place for z
    for (i=0; i<n; i++)
        z[i] = SWAP_BYTES(z[i]);
    
    //printf("%d, %p\n", n, z);
    
    ret = PyBytes_FromStringAndSize((char *)z, 4*n);
    free(z);
    z = NULL;
    
    return ret;
};


static PyObject* pysnow_f8(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: key, data (bytes buffer -> u8 *), count, bearer, dir, length (u32)
    Py_buffer key;
    Py_buffer data_py;
    u32 count, bearer, dir, length;
    int out_sz;
    // output: data (u8 * -> bytes buffer of size length in bits)
    u8 * data;
    
    if (! PyArg_ParseTuple(args, "z*IIIz*I", &key, &count, &bearer, &dir, &data_py, &length))
        return NULL;
    
    // transform length in bits to length in bytes
    out_sz = length >> 3;
    if (length % 8)
        out_sz++;
    
    if ((key.len != 16) || (dir > 1) || (out_sz > data_py.len))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    // duplicate the input buffer in order to not mutate it
    data = (u8 *)malloc(out_sz);
    if (data == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "malloc failed");
        return NULL;
    };
    memcpy(data, data_py.buf, out_sz);
    
    //void f8( u8 *key, u32 count, u32 bearer, u32 dir, u8 *data, u32 length );
    f8((u8 *)key.buf, count, bearer, dir, data, length);
    
    ret = PyBytes_FromStringAndSize((char *)data, out_sz);
    free(data);
    data = NULL;
    
    return ret;
};


static PyObject* pysnow_f9(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: key, data (bytes buffer -> u8 *), count, fresh, dir, length (u32)
    Py_buffer key;
    Py_buffer data;
    u32 count, fresh, dir, length;
    int out_sz;
    // output: mac (u8 * -> bytes buffer of size 4)
    u8 * mac;
    
    if (! PyArg_ParseTuple(args, "z*IIIz*I", &key, &count, &fresh, &dir, &data, &length))
        return NULL;
    
    // transform length in bits to length in bytes
    out_sz = length >> 3;
    if (length % 8)
        out_sz++;
    
    if ((key.len != 16) || (dir > 1) || (out_sz > data.len))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    //u8 * f9( u8* key, u32 count, u32 fresh, u32 dir, u8 *data, u64 length);
    mac = f9((u8 *)key.buf, count, fresh, dir, (u8 *)data.buf, length);
    
    ret = PyBytes_FromStringAndSize((char *)mac, 4);
    return ret;
};
