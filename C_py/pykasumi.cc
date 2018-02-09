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
 * File Name : CryptoMobile/pykasumi.c
 * Created : 2017-07-27 
 *--------------------------------------------------------
*/

#include <Python.h>
#include "../C_alg/Kasumi.h"


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

static PyObject* pykasumi_keyschedule(PyObject* dummy, PyObject* args);
static PyObject* pykasumi_kasumi(PyObject* dummy, PyObject* args);
static PyObject* pykasumi_f8(PyObject* dummy, PyObject* args);
static PyObject* pykasumi_f9(PyObject* dummy, PyObject* args);

static char pykasumi_keyschedule_doc[] =
    "kasumi_keyschedule(key [16 bytes]) -> None";
static char pykasumi_kasumi_doc[] =
    "kasumi_kasumi(clear_block [8 bytes]) -> ciphered_block [8 bytes]";
static char pykasumi_f8_doc[] =
    "kasumi_f8(ck [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
              "data_in [bytes], length [int, length in bits]) -> data_out [bytes]";
static char pykasumi_f9_doc[] =
    "kasumi_f9(ik [16 bytes], count [uint32], bearer [uint32], dir [0 or 1], "\
              "data_in [bytes], length [int, length in bits]) -> mac [4 bytes]";

static PyMethodDef pykasumi_methods[] = 
{
    //{exported name, function, args handling, doc string}
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"kasumi_keyschedule", pykasumi_keyschedule, METH_VARARGS, pykasumi_keyschedule_doc},
    {"kasumi_kasumi", pykasumi_kasumi, METH_VARARGS, pykasumi_kasumi_doc},
    {"kasumi_f8", pykasumi_f8, METH_VARARGS, pykasumi_f8_doc},
    {"kasumi_f9", pykasumi_f9, METH_VARARGS, pykasumi_f9_doc},
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

    static int pykasumi_traverse(PyObject *m, visitproc visit, void *arg) {
        Py_VISIT(GETSTATE(m)->error);
        return 0;
    }

    static int pykasumi_clear(PyObject *m) {
        Py_CLEAR(GETSTATE(m)->error);
        return 0;
    }

    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT,
            "pykasumi",
            "bindings for Kasumi F8 and F9 UMTS cryptographic functions",
            sizeof(struct module_state),
            pykasumi_methods,
            NULL,
            pykasumi_traverse,
            pykasumi_clear,
            NULL
    };

    #define INITERROR return NULL

    PyObject * PyInit_pykasumi(void)

#else

    #define INITERROR return

    void initpykasumi(void)

#endif

{
    #if PY_MAJOR_VERSION >= 3
    
        PyObject *module = PyModule_Create(&moduledef);
    
    #else
    
        PyObject *module = Py_InitModule4(
            "pykasumi",
            pykasumi_methods,
            "bindings for Kasumi F8 and F9 UMTS cryptographic functions",
            0,
            PYTHON_API_VERSION);
    
    #endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("pykasumi.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    #if PY_MAJOR_VERSION >= 3
    
        return module;
    
    #endif
}


/* pykasumi binding to Kasumi.h */


static PyObject* pykasumi_keyschedule(PyObject* dummy, PyObject* args)
{
    // input: key (bytes buffer -> u8 *)
    Py_buffer key;
    
    if (! PyArg_ParseTuple(args, "z*", &key))
        return NULL;
    
    if (key.len != 16)
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    //void KeySchedule( u8 *key );
    KeySchedule((u8 *)key.buf);
    
    Py_RETURN_NONE;
};


static PyObject* pykasumi_kasumi(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: data (bytes buffer -> u8 *)
    Py_buffer data_py;
    // output
    u8 data[8];
    
    if (! PyArg_ParseTuple(args, "z*", &data_py))
        return NULL;
    
    if (data_py.len != 8)
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    // duplicate the input buffer in order to not mutate it
    memcpy(data, data_py.buf, 8);
    
    //void Kasumi( u8 *data );
    Kasumi(data);
    
    ret = PyBytes_FromStringAndSize((char *)data, 8);
    return ret;
};


static PyObject* pykasumi_f8(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: key, data (bytes buffer -> u8 *), count, bearer, dir (u32), length (int, in bits)
    Py_buffer key;
    Py_buffer data_py;
    u32 count, bearer, dir;
    int length, out_sz;
    // output: data (u8 * -> bytes buffer of size length in bits
    u8 * data;
    
    if (! PyArg_ParseTuple(args, "z*IIIz*i", &key, &count, &bearer, &dir, &data_py, &length))
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
    
    //void f8( u8 *key, u32 count, u32 bearer, u32 dir, u8 *data, int length );
    f8((u8 *)key.buf, count, bearer, dir, data, length);
    
    ret = PyBytes_FromStringAndSize((char *)data, out_sz);
    free(data);
    data = NULL;
    
    return ret;
};


static PyObject* pykasumi_f9(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: key, data (bytes buffer -> u8 *), count, fresh, dir (u32), length (int, in bits)
    Py_buffer key;
    Py_buffer data;
    u32 count, fresh, dir;
    int length, out_sz;
    // output: mac (u8 * -> bytes buffer of size 4)
    u8 * mac;
    
    if (! PyArg_ParseTuple(args, "z*IIIz*i", &key, &count, &fresh, &dir, &data, &length))
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
    
    //u8 * f9( u8 *key, u32 count, u32 fresh, u32 dir, u8 *data, int length );
    mac = f9((u8 *)key.buf, count, fresh, dir, (u8 *)data.buf, length);
    
    ret = PyBytes_FromStringAndSize((char *)mac, 4);
    return ret;
};
