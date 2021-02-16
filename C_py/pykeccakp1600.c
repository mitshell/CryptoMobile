/**
 * Software Name : CryptoMobile 
 * Version : 0.2.0
 *
 * Copyright 2018. Benoit Michau. P1Sec.
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
 * File Name : CryptoMobile/pykeccakp1600.c
 * Created : 2018-12-18
 *--------------------------------------------------------
*/

#include <Python.h>
#include "../C_alg/KeccakP-1600-3gpp.h"


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

static PyObject* pykeccakp1600(PyObject* dummy, PyObject* args);
//static PyObject* push_data(PyObject* dummy, PyObject* args);

static char pykeccakp1600_doc[] =
    " pykeccakp1600(data_in [200 bytes]) -> data_out [200 bytes]";

static PyMethodDef pykeccakp1600_methods[] = 
{
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"pykeccakp1600", pykeccakp1600, METH_VARARGS, pykeccakp1600_doc},
//    {"push_data", push_data, METH_VARARGS, NULL},
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

    static int pykeccakp1600_traverse(PyObject *m, visitproc visit, void *arg) {
        Py_VISIT(GETSTATE(m)->error);
        return 0;
    }

    static int pykeccakp1600_clear(PyObject *m) {
        Py_CLEAR(GETSTATE(m)->error);
        return 0;
    }

    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT,
            "pykeccakp1600",
            "bindings for the Keccak P-1600 permutation cryptographic 64-bit functions",
            sizeof(struct module_state),
            pykeccakp1600_methods,
            NULL,
            pykeccakp1600_traverse,
            pykeccakp1600_clear,
            NULL
    };

    #define INITERROR return NULL

    PyObject * PyInit_pykeccakp1600(void)

#else

    #define INITERROR return

    void initpykeccakp1600(void)

#endif

{
    #if PY_MAJOR_VERSION >= 3
    
        PyObject *module = PyModule_Create(&moduledef);
    
    #else
    
        PyObject *module = Py_InitModule4(
            "pykeccakp1600",
            pykeccakp1600_methods,
            "bindings for the Keccak P-1600 permutation cryptographic 64-bit functions",
            0,
            PYTHON_API_VERSION);
    
    #endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("pykeccakp1600.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    #if PY_MAJOR_VERSION >= 3
    
        return module;
    
    #endif
}


// utiliy function required for handling (char *) to (uint64 *) conversion

uint64_t swap_uint64( uint64_t val )
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}

/* 
   pykeccakp1600 binding to the Keccak_f_64() function 
   as defined in KeccakP-1600-3gpp.h
*/

static PyObject* pykeccakp1600(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: state (200 bytes buffer -> void *)
    Py_buffer data_in;
    uint64_t state[25];
    //uint8_t i;
    
    if (! PyArg_ParseTuple(args, "z*", &data_in))
        return NULL;
    
    if (data_in.len != 200)
    {
        PyErr_SetString(PyExc_ValueError, "invalid arg, must be 200 bytes");
        return NULL;
    };
    
    memcpy(state, data_in.buf, 200);
    /* no need to swap bytes actually... who knows !
    for (i=0; i < 25; i++) {
        state[i] = swap_uint64(state[i]);
    }
    */
    
    //void Keccak_f_64(uint64 *s)
    Keccak_f_64(state);
    
    /*
    for (i=0; i < 25; i++) {
        state[i] = swap_uint64(state[i]);
    }
    */
    ret = PyBytes_FromStringAndSize((char *)state, 200);
    
    return ret;
};


/*
void PUSH_DATA_64(uint64_t * INOUT, uint8_t * data, uint8_t n, uint8_t location)
{
    while(n--)
		INOUT[location>>3] |= ((uint64_t)data[n]) << ((location++ & 7)<<3);
};

void PUSH_DATA_32(uint32_t * INOUT, uint8_t * data, uint8_t n, uint8_t location)
{
    while(n--)
		INOUT[location>>2] |= ((uint32_t)data[n]) << ((location++ & 3)<<3);
};

void PUSH_DATA_8(uint8_t * INOUT, uint8_t * data, uint8_t n, uint8_t location)
{
    while(n--)
		INOUT[location++] = data[n];
};


static PyObject* push_data(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: state (200 bytes buffer -> void *)
    Py_buffer data;
    uint8_t location;
    //uint64_t INOUT[25];
    //uint32_t INOUT[50];
    uint8_t  INOUT[200];
    
    if (! PyArg_ParseTuple(args, "z*b", &data, &location))
        return NULL;
    
    if (data.len > 255 || location > 199)
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    };
    
    memset(INOUT, 0, 200);
    
    //PUSH_DATA_64(INOUT, (uint8_t *)data.buf, (uint8_t)(data.len<<3), location);
    //PUSH_DATA_32(INOUT, (uint8_t *)data.buf, (uint8_t)(data.len<<3), location);
    PUSH_DATA_8 (INOUT, (uint8_t *)data.buf, (uint8_t)(data.len<<3), location);
    
    ret = PyBytes_FromStringAndSize((char *)INOUT, 200);
    return ret;
};
*/
