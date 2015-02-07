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
 * Revision 2.12.2.1.2.1  2015/02/05 23:42:40  customdesigned
 * New libdspam API builds.
 *
 * Revision 2.12.2.1  2003/12/18 16:45:33  stuart
 * Release 1.1.5 with its own RPM
 *
 * Revision 2.12  2003/09/06 04:20:54  stuart
 * ctx->message is an INOUT parameter, so destroy after dspam_process
 *
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

//#include <pthread.h>
#include <Python.h>
#include <structmember.h>
#include <dspam/libdspam.h>

/* These functions are not exported, but are necessary to replicate
 * the functionality of dspam. */

static PyObject *DspamError;

staticforward PyTypeObject dspam_Type;

typedef struct {
  PyObject_HEAD
  DSPAM_CTX *ctx;	/* Dspam dictionary handle */
  int mode;
  PyObject *sig;
} dspam_Object;

static void
_dspam_dealloc(PyObject *s) {
  dspam_Object *self = (dspam_Object *)s;
  DSPAM_CTX *ctx = self->ctx;
  if (ctx)
    dspam_destroy(ctx);
  Py_XDECREF(self->sig);
  //PyObject_DEL(s);
  self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
_dspam_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  dspam_Object *self;

  assert(type != NULL && type->tp_alloc != NULL);

  self = (dspam_Object *)type->tp_alloc(type,0);
  if (self != 0) {
    self->ctx = 0;
    self->mode = 0;
    self->sig = 0;
  }
  return (PyObject *)self;
}

static int
_dspam_init(PyObject *dspam, PyObject *args, PyObject *kwds) {
  dspam_Object *self = (dspam_Object *)dspam;
  static char *kwlist[] = {"name", "mode", "flags", "group", "home", 0};
  const char *username = 0;
  int flags = 0;
  const char *group = 0;
  const char *home = 0;
  if (self->ctx) {
    dspam_destroy(self->ctx);
    self->ctx = 0;
  }
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "si|iss:dspam", kwlist,
    &username,&self->mode,&flags,&group,&home)) return -1;
  self->ctx = dspam_create(username,group,home,self->mode,flags);
  if (self->ctx == 0) {
    PyErr_SetString(DspamError, "Context init failed");
    return -1;
  }
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
  if (self->mode == DSM_PROCESS || !(ctx->flags & DSF_SIGNATURE)) {
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
    if (self->mode == DSM_PROCESS) {
      if (!self->sig || PySequence_Size(self->sig) != len) {
	Py_XDECREF(self->sig);
	self->sig = PyBuffer_New(len);
      }
      if (self->sig) {
	void *data;
	Py_ssize_t dlen;
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
	rc,strerror(rc),ctx->username);
    if (e) PyErr_SetObject(DspamError, e);
    return NULL;
  }
  PyErr_SetString(DspamError, "DSPAM operation error");
  return NULL;
}

/* convert token dictionary to a Python dictionary */
static PyObject *toDict(ds_diction_t freq) {
  PyObject *dict = PyDict_New();
  if (dict == 0) return NULL;
  ds_cursor_t cur = ds_diction_cursor(freq);
  if (cur == 0) return PyErr_NoMemory();
  ds_term_t node_lht = ds_diction_next(cur);
  while (node_lht != 0) {
    PyObject *key = PyLong_FromUnsignedLongLong(node_lht->key);
    PyObject *tok = Py_BuildValue("(si)",
	node_lht->name,node_lht->frequency);
    if (!key || !tok || PyDict_SetItem(dict,key,tok)) {
      Py_XDECREF(key);
      Py_XDECREF(tok);
      Py_XDECREF(dict);
      dict = NULL;
      break;
    }
    node_lht = ds_diction_next(cur);
  } 
  ds_diction_close(cur);
  return dict;
}

static char _dspam_tokenize__doc__[] =
"tokenize(header,body,chained) -> dict\n\
  Tokenize the header and body using the dspam algorithm, and\n\
  return a dictionary of token name and frequency by crc64 key.";

static PyObject *
_dspam_tokenize(PyObject *dspamobj, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamobj;
  char *header = 0;
  char *body = 0;
  int chained = 1;
  int rc;
  ds_diction_t freq;
  PyObject *dict = 0;
  if (!PyArg_ParseTuple(args, "zz|i:tokenize",&header,&body,&chained))
  	return NULL;
  if (header == 0) header = " ";
  if (body == 0) body = " ";
  /* Tokenize scribbles on header and body text, so copy first. */
  header = strdup(header);
  body = strdup(body);
  freq = ds_diction_create(1000);
  if (header == 0 || body == 0 || freq == 0) {
    free(header);
    free(body);
    ds_diction_destroy(freq);
    return PyErr_NoMemory();
  }

  rc = _ds_tokenize(self->ctx,header,body,freq);
  free(header);
  free(body);
  /* convert token dictionary to a Python dictionary */
  if (rc)
    PyErr_NoMemory();
  else
    dict = toDict(freq);
  ds_diction_destroy(freq);
  return dict;
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

static char _dspam_attach__doc__[] =
"attach(dbh) -> None\n\
  Attach storage interface to context.";

static PyObject *
_dspam_attach(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  PyObject *dbh = 0;
  if (!PyArg_ParseTuple(args, "|O:attach",&dbh)) return NULL;
  if (!ctx) {
    PyErr_SetString(PyExc_TypeError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (dspam_attach(ctx,dbh)) {
    PyErr_SetString(PyExc_TypeError, "Failed to attach storage");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_generic_getstring(void *obj, int offset) {
  if (obj) {
    char **p = (char **)((void *)obj + offset);
    return Py_BuildValue("s",*p);
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_generic_getint(void *obj, int offset) {
  if (obj) {
    int *p = (int *)((void *)obj + offset);
    return Py_BuildValue("i",*p);
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static int
_generic_setint(void *obj, PyObject *value, const char *name, int offset) {
  char buf[80];
  int val;
  if (obj == NULL) {
    PyErr_SetString(PyExc_TypeError, "DSPAM context not active");
    return -1;
  }
  if (value == NULL) {
    sprintf(buf,"Cannot delete %s",name);
    PyErr_SetString(PyExc_TypeError, buf);
    return -1;
  }
  if (! PyInt_Check(value)) {
    sprintf(buf,"%s must be an int",name);
    PyErr_SetString(PyExc_TypeError, buf);
    return -1;
  }

  val = (int)PyInt_AsLong(value);
  if (PyErr_Occurred())
    return -1;
  else {
    int *p = (int *)((void *)obj + offset);
    *p = val;
  }
  return 0;
}

static PyObject *
_dspam_getresult(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,result));
}

static PyObject *
_dspam_gettokenizer(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,tokenizer));
}

static int
_dspam_settokenizer(dspam_Object *self, PyObject *value, void *closure) {
  return _generic_setint(self->ctx,value,"tokenizer",offsetof(DSPAM_CTX,tokenizer));
}

static PyObject *
_dspam_getsource(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,source));
}

static int
_dspam_setsource(dspam_Object *self, PyObject *value, void *closure) {
  return _generic_setint(self->ctx,value,"source",offsetof(DSPAM_CTX,source));
}

static PyObject *
_dspam_getalgorithms(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,algorithms));
}

static int
_dspam_setalgorithms(dspam_Object *self, PyObject *value, void *closure) {
  return _generic_setint(self->ctx,value,"algorithms",offsetof(DSPAM_CTX,algorithms));
}

static PyObject *
_dspam_getclassification(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,classification));
}

static int
_dspam_setclassification(dspam_Object *self, PyObject *value, void *closure) {
  return _generic_setint(self->ctx,value,"classification",offsetof(DSPAM_CTX,classification));
}

static PyObject *
_dspam_gettraining_mode(dspam_Object *self, void *closure) {
  return _generic_getint(self->ctx,offsetof(DSPAM_CTX,training_mode));
}

static int
_dspam_settraining_mode(dspam_Object *self, PyObject *value, void *closure) {
  return _generic_setint(self->ctx,value,"training_mode",offsetof(DSPAM_CTX,training_mode));
}

static PyObject *
_dspam_getprob(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) return Py_BuildValue("f",ctx->probability);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_dspam_getusername(dspam_Object *self, void *closure) {
  return _generic_getstring(self->ctx,offsetof(DSPAM_CTX,username));
}

static PyObject *
_dspam_getgroup(dspam_Object *self, void *closure) {
  return _generic_getstring(self->ctx,offsetof(DSPAM_CTX,group));
}

static PyObject *
_dspam_gethome(dspam_Object *self, void *closure) {
  return _generic_getstring(self->ctx,offsetof(DSPAM_CTX,home));
}

static PyObject *
_dspam_gettot(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx) 
    return Py_BuildValue("(iiiiiiii)",
      ctx->totals.spam_learned,ctx->totals.innocent_learned,
      ctx->totals.spam_misclassified,ctx->totals.innocent_misclassified,
      ctx->totals.spam_corpusfed,ctx->totals.innocent_corpusfed,
      ctx->totals.spam_classified,ctx->totals.innocent_classified
    );
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef dspamctx_methods[] = {
  { "attach", _dspam_attach, METH_VARARGS, _dspam_attach__doc__},
  { "process", _dspam_process, METH_VARARGS, _dspam_process__doc__},
  { "tokenize", _dspam_tokenize, METH_VARARGS, _dspam_tokenize__doc__},
  { "destroy", _dspam_destroy, METH_VARARGS, _dspam_destroy__doc__},
  { NULL, NULL }
};

static PyMemberDef dspamctx_members[] = {
  { "signature",T_OBJECT,offsetof(dspam_Object,sig),RO,
    "Statistical Signature of message" },
  {0},
};

static PyGetSetDef dspamctx_getsets[] = {
  { "result",(getter)_dspam_getresult,NULL, "Result of processing: DSR_*" },
  { "tokenizer",(getter)_dspam_gettokenizer,(setter)_dspam_settokenizer,
  	"Tokenizer algorithm: DSZ_*" },
  { "source",(getter)_dspam_getsource,(setter)_dspam_setsource,
  	"Source of classification: DSS_*" },
  { "classification",
  	(getter)_dspam_getclassification,(setter)_dspam_setclassification,
  	"Classification: DSR_*" },
  { "algorithms",
  	(getter)_dspam_getalgorithms,(setter)_dspam_setalgorithms,
  	"Algorithms: DSA_*" },
  { "training_mode",
  	(getter)_dspam_gettraining_mode,(setter)_dspam_settraining_mode,
  	"Training Mode: DST_*" },
  { "probability", (getter)_dspam_getprob, NULL, "Probability of SPAM" },
  { "username", (getter)_dspam_getusername, NULL, "User name" },
  { "group", (getter)_dspam_getgroup, NULL, "Group name" },
  { "home", (getter)_dspam_gethome, NULL, "DSPAM home" },
  { "totals", (getter)_dspam_gettot, NULL, "(SPAM,INNOCENT,MISS,FP)" },
  {NULL},
};

static char _dspam_init_driver__doc__[] =
"init_driver() -> None\n\
  Call once when your application starts.";

static PyObject *
_dspam_init_driver(PyObject *self, PyObject *args) {
  PyObject *driver_ctx;
  if (!PyArg_ParseTuple(args, "O:init_driver",&driver_ctx)) return NULL;
  if (dspam_init_driver(NULL)) {
    PyErr_SetString(DspamError, "Unable to initialize driver");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_shutdown_driver__doc__[] =
"init_driver() -> None\n\
  Perform driver specific shutdown functions.";

static PyObject *
_dspam_shutdown_driver(PyObject *self, PyObject *args) {
  PyObject *driver_ctx;
  if (!PyArg_ParseTuple(args, "O:shutdown_driver",&driver_ctx)) return NULL;
  dspam_init_driver(NULL);
  Py_INCREF(Py_None);
  return Py_None;
}

static char _libdspam_init__doc__[] =
"libdspam_init() -> None\n\
  Call once when your application starts.";

static PyObject *
_libdspam_init(PyObject *self, PyObject *args) {
  const char *driver;
  if (!PyArg_ParseTuple(args, "s:init",&driver)) return NULL;
  if (libdspam_init(driver)) {
    PyErr_SetString(DspamError, "Unable to initialize libdspam");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _libdspam_shutdown__doc__[] =
"libdspam_shutdown() -> None\n\
  Shutdown libdspam.";

static PyObject *
_libdspam_shutdown(PyObject *self, PyObject *args) {
  if (!PyArg_ParseTuple(args, ":shutdown")) return NULL;
  libdspam_shutdown();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef _dspam_methods[] = {
  { "libdspam_init",_libdspam_init, METH_VARARGS, _libdspam_init__doc__ },
  { "libdspam_shutdown",_libdspam_shutdown, METH_VARARGS, _libdspam_shutdown__doc__ },
  { "init_driver", _dspam_init_driver, METH_VARARGS, _dspam_init_driver__doc__},
  { "shutdown_driver", _dspam_shutdown_driver, METH_VARARGS, _dspam_shutdown_driver__doc__},
  { NULL, NULL }
};

static PyTypeObject dspam_Type = {
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "dspam.ctx",
  sizeof(dspam_Object),
  	0,					/* itemsize */
        (destructor)_dspam_dealloc,            /* tp_dealloc */
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
   if (PyDict_SetItemString(d,"ctx", (PyObject *)&dspam_Type)) return;
#define CONST(n) PyModule_AddIntConstant(m,#n, n)
/* DSPAM Flags */
   CONST(DSF_UNLEARN);
   CONST(DSF_BIAS);
   CONST(DSF_SIGNATURE);
   CONST(DSF_NOISE);
   CONST(DSF_WHITELIST);
   CONST(DSF_MERGED);

/* DSPAM Processor modes */
   CONST(DSM_PROCESS);
   CONST(DSM_CLASSIFY);
   CONST(DSM_TOOLS);
/* Classifications */
   CONST(DSR_ISSPAM);
   CONST(DSR_ISINNOCENT);
   CONST(DSR_NONE);
/* Source of Classification */
   CONST(DSS_ERROR);	/* Misclassification by dspam */
   CONST(DSS_CORPUS);	/* Corpus fed message */
   CONST(DSS_INOCULATION); /* Message inoculation */
   CONST(DSS_NONE);	/* No source - use only with DSR_NONE */
/* Tokenizers */
   CONST(DSZ_WORD);
   CONST(DSZ_CHAIN);
   CONST(DSZ_SBPH);
   CONST(DSZ_OSB);
/* Training Modes */
   CONST(DST_TEFT);	/* Train on everything */
   CONST(DST_TOE);	/* Train on error */
   CONST(DST_TUM);	/* Train until mature */
/* Algorithms */
   CONST(DSA_GRAHAM);	/* Graham-Bayesian */
   CONST(DSP_GRAHAM);	/* Graham-Bayesian */
   CONST(DSA_BURTON);	/* Burton-Bayesian */
   CONST(DSA_ROBINSON);	/* Robinson's Geometric Mean Test */
   CONST(DSP_ROBINSON);	/* Robinson's Geometric Mean Test */
   CONST(DSA_CHI_SQUARE); /* Fischer-Robinson's Chi-Square */
   CONST(DSP_MARKOV);
   CONST(DSA_NAIVE);	/* Naive Bayesian */
#ifdef DSR_ISWHITELISTED
   CONST(DSR_ISWHITELISTED);
#endif
}
