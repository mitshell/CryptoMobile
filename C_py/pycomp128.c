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
 * File Name : CryptoMobile/pycomp128.c
 * Created : 2017-07-27 
 *--------------------------------------------------------
*/

#include <Python.h>
#include "../C_alg/comp128.h"


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

static PyObject* pycomp128v1(PyObject* dummy, PyObject* args);
static PyObject* pycomp128v2(PyObject* dummy, PyObject* args);
static PyObject* pycomp128v3(PyObject* dummy, PyObject* args);

static char pycomp128v1_doc[] =
    "comp128v1(ki [16 bytes], rand [16 bytes]) -> (sres [4 bytes], kc [8 bytes])";
static char pycomp128v2_doc[] =
    "comp128v2(ki [16 bytes], rand [16 bytes]) -> (sres [4 bytes], kc [8 bytes])";
static char pycomp128v3_doc[] =
    "comp128v3(ki [16 bytes], rand [16 bytes]) -> (sres [4 bytes], kc [8 bytes])";

static PyMethodDef pycomp128_methods[] = 
{
    //{exported name, function, args handling, doc string}
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"comp128v1", pycomp128v1, METH_VARARGS, pycomp128v1_doc},
    {"comp128v2", pycomp128v2, METH_VARARGS, pycomp128v2_doc},
    {"comp128v3", pycomp128v3, METH_VARARGS, pycomp128v3_doc},
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

    static int pycomp128_traverse(PyObject *m, visitproc visit, void *arg) {
        Py_VISIT(GETSTATE(m)->error);
        return 0;
    }

    static int pycomp128_clear(PyObject *m) {
        Py_CLEAR(GETSTATE(m)->error);
        return 0;
    }

    static struct PyModuleDef moduledef = {
            PyModuleDef_HEAD_INIT,
            "pycomp128",
            "bindings for Comp128 GSM authentication algorithms",
            sizeof(struct module_state),
            pycomp128_methods,
            NULL,
            pycomp128_traverse,
            pycomp128_clear,
            NULL
    };

    #define INITERROR return NULL

    PyObject * PyInit_pycomp128(void)

#else

    #define INITERROR return

    void initpycomp128(void)

#endif

{
    #if PY_MAJOR_VERSION >= 3
    
        PyObject *module = PyModule_Create(&moduledef);
    
    #else
    
        PyObject *module = Py_InitModule4(
            "pycomp128",
            pycomp128_methods,
            "bindings for Comp128 GSM authentication algorithms",
            0,
            PYTHON_API_VERSION);
    
    #endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("pycomp128.Error", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }

    #if PY_MAJOR_VERSION >= 3
    
        return module;
    
    #endif
}


/* pycomp128 binding to comp128.h */


static PyObject* pycomp128v1(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: ki, rand (bytes buffer -> const uint8_t*)
    Py_buffer ki;
    Py_buffer rand;
    // output: sres, kc (uint8_t* -> bytes buffer)
    uint8_t sres[4];
    uint8_t kc[8];
    
    if (! PyArg_ParseTuple(args, "z*z*", &ki, &rand))
        return NULL;
    
    if ( (ki.len != 16) || (rand.len != 16) ) {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }
    
    //void comp128v1(uint8_t *sres, uint8_t *kc, const uint8_t *ki, const uint8_t *rand);
    comp128v1(sres, kc, (const uint8_t *)ki.buf, (const uint8_t *)rand.buf);
    
    ret = PyTuple_New(2);
    PyTuple_SetItem(ret, 0, PyBytes_FromStringAndSize((char *)sres, 4));
    PyTuple_SetItem(ret, 1, PyBytes_FromStringAndSize((char *)kc, 8));
    return ret;
};


static PyObject* pycomp128v2(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: ki, rand (bytes buffer -> const uint8_t*)
    Py_buffer ki;
    Py_buffer rand;
    // output: sres, kc (uint8_t* -> bytes buffer)
    uint8_t sres[4];
    uint8_t kc[8];
    
    if (! PyArg_ParseTuple(args, "z*z*", &ki, &rand))
        return NULL;
    
    if ( (ki.len != 16) || (rand.len != 16) ) {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }
    
    //void comp128v23(uint8_t *sres, uint8_t *kc, uint8_t const *ki, uint8_t const *rand, bool v2);
    comp128v23(sres, kc, (const uint8_t *)ki.buf, (const uint8_t *)rand.buf, true);
    
    ret = PyTuple_New(2);
    PyTuple_SetItem(ret, 0, PyBytes_FromStringAndSize((char *)sres, 4));
    PyTuple_SetItem(ret, 1, PyBytes_FromStringAndSize((char *)kc, 8));
    return ret;
};


static PyObject* pycomp128v3(PyObject* dummy, PyObject* args)
{
    PyObject* ret = 0;
    
    // input: ki, rand (bytes buffer -> const uint8_t*)
    Py_buffer ki;
    Py_buffer rand;
    // output: sres, kc (uint8_t* -> bytes buffer)
    uint8_t sres[4];
    uint8_t kc[8];
    
    if (! PyArg_ParseTuple(args, "z*z*", &ki, &rand))
        return NULL;
    
    if ( (ki.len != 16) || (rand.len != 16) ) {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }
    
    //void comp128v23(uint8_t *sres, uint8_t *kc, uint8_t const *ki, uint8_t const *rand, bool v2);
    comp128v23(sres, kc, (const uint8_t *)ki.buf, (const uint8_t *)rand.buf, false);
    
    ret = PyTuple_New(2);
    PyTuple_SetItem(ret, 0, PyBytes_FromStringAndSize((char *)sres, 4));
    PyTuple_SetItem(ret, 1, PyBytes_FromStringAndSize((char *)kc, 8));
    return ret;
};
