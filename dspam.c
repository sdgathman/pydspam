/* Copyright (C) 2003  Stuart Gathman (stuart@bmsi.com)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/* This module interfaces Python to the dspam library.  Dspam can be
 * obtained from:
 *   http://www.networkdweebs.com/software/dspam/
 * Source and RedHat binary RPMS for dspam can be obtained from:
 *   http://bmsi.com/linux/rh72/
 */

/* 
 * $Log$
 * Revision 2.11  2003/09/03 04:27:29  stuart
 * incorrect free
 *
 * Revision 2.10  2003/09/03 04:15:51  stuart
 * No more copyback in dspam-2.6.5
 *
 * Revision 2.9  2003/08/30 04:46:57  stuart
 * Begin higher level framework: signature database and quarantine mbox
 *
 * Revision 2.8  2003/07/30 19:45:30  stuart
 * Pydspam project.
 *
 * Revision 2.6  2003/07/10 12:53:11  stuart
 * Python support
 *
 * Revision 2.5  2003/07/10 12:39:04  stuart
 * export tokenize
 *
 * Revision 2.4  2003/07/07 19:32:42  stuart
 * Support file_lock and file_unlock
 *
 * Revision 2.3  2003/07/03 16:22:45  stuart
 * Support DSF_CLASSIFY in dspam-2.6.2
 *
 * Revision 2.2  2003/06/30 21:25:44  stuart
 * DSPAM destroy() method to release resources
 *
 * Revision 2.1  2003/06/27 19:51:10  stuart
 * Add dspam interface.
 *
 */

#include <pthread.h>
#include <Python.h>
#include <structmember.h>
#include "../libdspam.h"

/* These functions are not exported, but are necessary to replicate
 * the functionality of dspam. */
int _ds_context_lock(DSPAM_CTX *);
int _ds_context_unlock(DSPAM_CTX *);
int _ds_file_lock(const char *);
int _ds_file_unlock(const char *);

static PyObject *DspamError;

staticforward PyTypeObject dspam_Type;

typedef struct {
  PyObject_HEAD
  DSPAM_CTX *ctx;	/* Dspam dictionary handle */
  PyObject *sig;
} dspam_Object;

static void
_dspam_dealloc(PyObject *s) {
  dspam_Object *self = (dspam_Object *)s;
  DSPAM_CTX *ctx = self->ctx;
  if (ctx)
    dspam_destroy(ctx);
  Py_XDECREF(self->sig);
  PyObject_DEL(self);
}

static PyObject *
_dspam_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  dspam_Object *self;

  assert(type != NULL && type->tp_alloc != NULL);

  self = (dspam_Object *)type->tp_alloc(type,0);
  if (self != 0) {
    self->ctx = 0;
    self->sig = 0;
  }
  return (PyObject *)self;
}

static int
_dspam_init(PyObject *dspam, PyObject *args, PyObject *kwds) {
  dspam_Object *self = (dspam_Object *)dspam;
  static char *kwlist[] = {"name", "mode", "flags", 0};
  const char *fname;
  int mode;
  int flags = 0;
  if (self->ctx) {
    dspam_destroy(self->ctx);
    self->ctx = 0;
  }
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "si|i:dspam", kwlist,
    &fname,&mode,&flags)) return -1;

  self->ctx = dspam_init(fname,mode,flags);
  if (self->ctx == 0) return -1;
  return 0;
}

static char _dspam_process__doc__[] =
"process(message) -> None\n\
  Process an email message stored as a string or buffer.\n\
  If DSF_SIGNATURE is set and mode is not DSM_PROCESS,\n\
  then message is a Buffer object obtained from the dspam.signature\n\
  property.";

static PyObject *
_dspam_process(PyObject *dspamobj, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamobj;
  DSPAM_CTX *ctx = self->ctx;
  char *message = 0;
  int rc;
  if (ctx == 0) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (ctx->mode == DSM_PROCESS || !(ctx->flags & DSF_SIGNATURE)) {
    if (!PyArg_ParseTuple(args, "s:process",&message)) return NULL;
  }
  else {
    ctx->signature = malloc(sizeof *ctx->signature);
    if (ctx->signature == 0) return PyErr_NoMemory();
    if (!PyArg_ParseTuple(args, "s#:process",
	  &ctx->signature->data,&ctx->signature->length)) return NULL;
  }
  rc = dspam_process(ctx,message);

  /* We don't need ctx->message, and it overrides the text message
   * if left in the context.  So destroy it now. */
  if (ctx->message) {
    _ds_destroy_message(ctx->message);
    ctx->message = 0;
  }

  /* Retrieve output fields.  It looks like caller is responsible
   * to free signature */
  if (ctx->signature) {
    char *buf = ctx->signature->data;
    int len = ctx->signature->length;
    free(ctx->signature);
    ctx->signature = 0;
    if (buf == 0) len = 0;
    if (ctx->mode == DSM_PROCESS) {
      if (!self->sig || PySequence_Size(self->sig) != len) {
	Py_XDECREF(self->sig);
	self->sig = PyBuffer_New(len);
      }
      if (self->sig) {
	void *data;
	int dlen;
	if (!PyObject_AsWriteBuffer(self->sig,&data,&dlen))
	  memcpy(data,buf,dlen);
	else {
	  Py_DECREF(self->sig);
	  self->sig = 0;
	}
      }
      /* buf is allocated by libdspam only in DSM_PROCESS mode,
       * otherwise it is allocated by the caller. */
      free(buf);
    }
  }
  else {
    Py_XDECREF(self->sig);
    self->sig = 0;
  }

  if (!rc) {
    Py_INCREF(Py_None);
    return Py_None;
  }

  /* report error as exception */
  rc = ctx->result;
  if (rc != -1) {
    PyObject *e = Py_BuildValue("iss",
	rc,db_strerror(rc),ctx->dictionary);
    if (e) PyErr_SetObject(DspamError, e);
    return NULL;
  }
  PyErr_SetString(DspamError, "DSPAM operation error");
  return NULL;
}

/* convert token dictionary to a Python dictionary */
static PyObject *toDict(struct lht *freq) {
  PyObject *dict = PyDict_New();
  struct lht_node *node_lht;
  struct lht_c c_lht;
  if (dict == 0) return PyErr_NoMemory();
  node_lht = c_lht_first(freq, &c_lht);
  while (node_lht != NULL) {
    PyObject *key = PyLong_FromUnsignedLongLong(node_lht->key);
    PyObject *tok = Py_BuildValue("(si)",
	node_lht->token_name,node_lht->frequency);
    if (!key || !tok || PyDict_SetItem(dict,key,tok)) {
      Py_XDECREF(key);
      Py_XDECREF(tok);
      Py_XDECREF(dict);
      return NULL;
    }
    node_lht = c_lht_next(freq, &c_lht);
  } 
  return dict;
}

static char _dspam_tokenize__doc__[] =
"tokenize(header,body,chained) -> dict\n\
  Tokenize the header and body using the dspam algorithm, and\n\
  return a dictionary of token name and frequency by crc64 key.";

static PyObject *
_dspam_tokenize(PyObject *module, PyObject *args) {
  char *header;
  char *body;
  int chained = 1;
  struct lht *freq;
  PyObject *dict;
  if (!PyArg_ParseTuple(args, "zz|i:tokenize",&header,&body)) return NULL;
  if (header == 0) header = " ";
  if (body == 0) body = " ";
  /* Tokenize scribbles on header and body text, so copy first. */
  header = strdup(header);
  if (header == 0) return PyErr_NoMemory();
  body = strdup(body);
  if (body == 0) {
    free(header);
    return PyErr_NoMemory();
  }
  freq = _ds_tokenize(chained,header,body);
  free(header);
  free(body);
  if (freq == 0) return PyErr_NoMemory();
  /* convert token dictionary to a Python dictionary */
  dict = toDict(freq);
  lht_destroy(freq);
  return dict;
}

static char _dspam_lock__doc__[] =
"lock() -> None\n\
  Lock the DSPAM context.  When used with the DSF_NOLOCK flag\n\
  allows the sig database and other data to be locked also.";

static PyObject *
_dspam_lock(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  if (!PyArg_ParseTuple(args, ":lock")) return NULL;
  if (!ctx || _ds_context_lock(ctx)) {
    PyErr_SetString(DspamError, "Lock failed");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_unlock__doc__[] =
"unlock() -> None\n\
  Unlock the DSPAM context.";

static PyObject *
_dspam_unlock(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  if (!PyArg_ParseTuple(args, ":unlock")) return NULL;
  if (ctx) _ds_context_unlock(ctx);
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_file_lock__doc__[] =
"file_lock(filename) -> None\n\
  Lock a file using the DSPAM locking protocol.\n\
  When used with the DSF_NOLOCK flag\n\
  allows the sig database and other data to be locked also.";

static PyObject *
_dspam_file_lock(PyObject *module, PyObject *args) {
  char *fname;
  if (!PyArg_ParseTuple(args, "s:file_lock",&fname)) return NULL;
  if (_ds_file_lock(fname)) {
    PyErr_SetString(DspamError, "Lock failed");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_file_unlock__doc__[] =
"file_unlock(filename) -> None\n\
  Unlock a file locked with file_lock().";

static PyObject *
_dspam_file_unlock(PyObject *module, PyObject *args) {
  char *fname;
  if (!PyArg_ParseTuple(args, "s:file_unlock",&fname)) return NULL;
  _ds_file_unlock(fname);
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_destroy__doc__[] =
"destroy() -> None\n\
  Release all resources for this DSPAM context.";

static PyObject *
_dspam_destroy(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  if (!PyArg_ParseTuple(args, ":destroy")) return NULL;
  if (ctx) {
    self->ctx = 0;
    dspam_destroy(ctx);
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_dspam_getresult(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) return Py_BuildValue("i",ctx->result);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_dspam_getprob(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) return Py_BuildValue("f",ctx->probability);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_dspam_getdict(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) return Py_BuildValue("s",ctx->dictionary);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_dspam_gettot(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) return Py_BuildValue("(iiii)",
      ctx->totals.total_spam,ctx->totals.total_innocent,
      ctx->totals.spam_misses,ctx->totals.false_positives);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef dspamctx_methods[] = {
  { "process", _dspam_process, METH_VARARGS, _dspam_process__doc__},
  { "lock", _dspam_lock, METH_VARARGS, _dspam_lock__doc__},
  { "unlock", _dspam_unlock, METH_VARARGS, _dspam_unlock__doc__},
  { "destroy", _dspam_destroy, METH_VARARGS, _dspam_destroy__doc__},
  { NULL, NULL }
};

static PyMemberDef dspamctx_members[] = {
  { "signature",T_OBJECT,offsetof(dspam_Object,sig),RO,
    "Statistical Signature of message" },
  {0},
};

static PyGetSetDef dspamctx_getsets[] = {
  { "result", (getter)_dspam_getresult, NULL, "Result of processing" },
  { "probability", (getter)_dspam_getprob, NULL, "Probability of SPAM" },
  { "dictionary", (getter)_dspam_getdict, NULL, "Dictionary file name" },
  { "totals", (getter)_dspam_gettot, NULL, "(SPAM,INNOCENT,MISS,FP)" },
  {NULL},
};

static PyMethodDef _dspam_methods[] = {
   { "tokenize", _dspam_tokenize, METH_VARARGS, _dspam_tokenize__doc__},
   { "file_lock",_dspam_file_lock,METH_VARARGS,_dspam_file_lock__doc__},
   { "file_unlock",_dspam_file_unlock,METH_VARARGS,_dspam_file_unlock__doc__},
   { NULL, NULL }
};

static PyTypeObject dspam_Type = {
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "dspam",
  sizeof(dspam_Object),
  0,
        _dspam_dealloc,            /* tp_dealloc */
        0,               /* tp_print */
        0,           /* tp_getattr */
        0,			/* tp_setattr */
        0,                                      /* tp_compare */
        0,                 /* tp_repr */
        0,                     /* tp_as_number */
        0,                                      /* tp_as_sequence */
        0,                                      /* tp_as_mapping */
        0,                 /* tp_hash */
        0,                                      /* tp_call */
        0,                  /* tp_str */
        PyObject_GenericGetAttr,		/* tp_getattro */
        0,                                      /* tp_setattro */
        0,                                      /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,/* tp_flags */
	"DSPAM context object",		/* tp_doc */
	0,		/* tp_traverse */
        0,                                      /* tp_clear */
	0,                    /* tp_richcompare */
	0,                                      /* tp_weaklistoffset */
	0,                                      /* tp_iter */
	0,                                      /* tp_iternext */
	dspamctx_methods,                       /* tp_methods */
	dspamctx_members, 			/* tp_members */
	dspamctx_getsets,			/* tp_getset */
        0,                                      /* tp_base */
	0,                                      /* tp_dict */
	0,                                      /* tp_descr_get */
	0,                                      /* tp_descr_set */
	0,                                      /* tp_dictoffset */
	(initproc)_dspam_init,                  /* tp_init */
	PyType_GenericAlloc,                    /* tp_alloc */
	_dspam_new,                             /* tp_new */
	_PyObject_Del,                 		/* tp_free */
};

static char _dspam_documentation[] =
"This module wraps the libdspam library API for the DSPAM Bayesian\n\
anti-spam package.\n";

void
initdspam(void) {
   PyObject *m, *d;

   m = Py_InitModule4("dspam", _dspam_methods, _dspam_documentation,
		      (PyObject*)NULL, PYTHON_API_VERSION);
   d = PyModule_GetDict(m);
   DspamError = PyErr_NewException("dspam.error", PyExc_EnvironmentError, NULL);
   if (!DspamError) return;
   if (PyDict_SetItemString(d,"error", DspamError)) return;
   if (PyDict_SetItemString(d,"dspam", (PyObject *)&dspam_Type)) return;
   /* init is a synonym for dspam type */
   if (PyDict_SetItemString(d,"init", (PyObject *)&dspam_Type)) return;
#define CONST(n) PyModule_AddIntConstant(m,#n, n)
/* DSPAM Flags */
   CONST(DSF_CHAINED); CONST(DSF_SIGNATURE);
   CONST(DSF_NOLOCK); CONST(DSF_COPYBACK);
   CONST(DSF_IGNOREHEADER); CONST(DSF_CORPUS);
#ifdef DSF_CLASSIFY
   CONST(DSF_CLASSIFY);
#endif
/* DSPAM Processor modes */
   CONST(DSM_PROCESS); CONST(DSM_ADDSPAM); CONST(DSM_FALSEPOSITIVE);
/* DSPAM Results */
   CONST(DSR_ISSPAM); CONST(DSR_ISINNOCENT);
}
