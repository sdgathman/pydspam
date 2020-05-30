/* Copyright (C) 2003,2015  Stuart Gathman (stuart@bmsi.com)
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
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* This module interfaces Python to the dspam library.  Dspam can be
 * obtained from:
 *   http://www.networkdweebs.com/software/dspam/
 * Source and RedHat binary RPMS for dspam can be obtained from:
 *   http://bmsi.com/linux/rh72/
 */

/* 
 * $Log$
 * Revision 2.17  2015/02/14 19:23:37  customdesigned
 * Another crasher typo fixed.
 *
 * Revision 2.16  2015/02/14 18:55:04  customdesigned
 * Add set_verified_user method
 *
 * Revision 2.15  2015/02/14 15:40:10  customdesigned
 * Crasher typo fixed.
 *
 * Revision 2.14  2015/02/11 22:06:03  customdesigned
 * Merge pydspam-3-branch to trunk
 *
 * Revision 2.12.2.1.2.7  2015/02/10 03:13:20  customdesigned
 * Reverse args for set_signature
 *
 * Revision 2.12.2.1.2.6  2015/02/10 00:50:33  customdesigned
 * Add factors attribute.
 *
 * Revision 2.12.2.1.2.5  2015/02/10 00:06:39  customdesigned
 * Add *_fcntl_lock and get/set/delete/verify signature.
 *
 * Revision 2.12.2.1.2.4  2015/02/09 16:58:13  customdesigned
 * Fix signature handling.
 *
 * Revision 2.12.2.1.2.3  2015/02/08 00:07:34  customdesigned
 * Start of Documentation, and more details of wrapping done.
 *
 * Revision 2.12.2.1.2.2  2015/02/07 06:30:51  customdesigned
 * libdspam_init() and ctx.attach()
 *
 * Revision 2.12.2.1.2.1  2015/02/05 23:42:40  customdesigned
 * New libdspam API builds.
 */

//#include <pthread.h>
#include <Python.h>
#include <structmember.h>
//#define DEBUG 2		// if libdspam compiled with --enable-debug 
#include <dspam/auto-config.h>
#include <dspam/util.h>
#include <dspam/libdspam.h>

/* These functions are not exported, but are necessary to replicate
 * the functionality of dspam. */

int verified_user = 1;

static PyObject *DspamError;

#if PY_MAJOR_VERSION >= 3
	static PyTypeObject dspam_Type;
#else
	staticforward PyTypeObject dspam_Type;
#endif

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
  PyObject_DEL(self);
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
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "zi|izz:dspam", kwlist,
    &username,&self->mode,&flags,&group,&home)) return -1;
  self->ctx = dspam_create(username,group,home,self->mode,flags);
  if (self->ctx == 0) {
    PyErr_NoMemory();
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
_dspam_process(PyObject *dspamobj, PyObject *args, PyObject *kwds) {
  dspam_Object *self = (dspam_Object *)dspamobj;
  DSPAM_CTX *ctx = self->ctx;
  const char *message;
  struct _ds_spam_signature sig;
  char *data = 0;
  int len;
  int rc;
  static char *kwlist[] = {"msg", "sig", 0};
  if (ctx == 0) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (ctx->signature) {
    free(ctx->signature->data);
    free(ctx->signature);
    ctx->signature = 0;
  }
#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "y|z#:process", kwlist,
      &message,&data,&len)) return NULL;
#else
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "z|z#:process", kwlist,
      &message,&data,&len)) return NULL;
#endif
  if (message && !*message) message = NULL;
  if (data) {
    sig.data = data;
    sig.length = len;
    ctx->signature = &sig;
  }

  rc = dspam_process(ctx,message);
  /* If we passed in signature, it was temp data, so unreference now. */
  if (data) {
    ctx->signature = NULL;
    ctx->_sig_provided = 0;
  }

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
    Py_ssize_t len = ctx->signature->length;
    free(ctx->signature);
    ctx->signature = 0;
    if (buf == 0) len = 0;
    if (!self->sig || PySequence_Size(self->sig) != len) {
      Py_XDECREF(self->sig);
#if PY_MAJOR_VERSION >= 3
      self->sig = PyByteArray_FromStringAndSize(buf,len);
      free(buf);
      buf = 0; len = 0;
#else
      self->sig = PyBuffer_New(len);
#endif
    }
    if (self->sig && buf) {
      void *data;
      Py_ssize_t dlen;
      if (!PyObject_AsWriteBuffer(self->sig,&data,&dlen))
	memcpy(data,buf,dlen);
      else {
	Py_DECREF(self->sig);
	self->sig = 0;
      }
    }
    free(buf);
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
    PyObject *e = Py_BuildValue("(iss)",
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
"tokenize(header,body) -> dict\n\
  Tokenize the header and body using the algorithm, and\n\
  return a dictionary of token name and frequency by crc64 key.";

static PyObject *
_dspam_tokenize(PyObject *dspamobj, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamobj;
  char *header = 0;
  char *body = 0;
  int rc;
  ds_diction_t freq;
  PyObject *dict = 0;
  if (!PyArg_ParseTuple(args, "zz|i:tokenize",&header,&body))
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

static char _dspam_addattribute__doc__[] =
"addattribute(key,val) -> None\n\
  Add DSPAM configuration attribute.";

static PyObject *
_dspam_addattribute(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  char *key = 0, *val = 0;
  if (!PyArg_ParseTuple(args, "ss:addattribute",&key,&val)) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (dspam_addattribute(ctx,key,val)) return PyErr_NoMemory();
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_clearattributes__doc__[] =
"clearattributes() -> None\n\
  Clear all DSPAM configuration attributes.";

static PyObject *
_dspam_clearattributes(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  if (!PyArg_ParseTuple(args, ":clearattributes")) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (dspam_clearattributes(ctx)) return PyErr_NoMemory();
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
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (ctx->storage) {
    PyErr_SetString(DspamError, "Storage already attached to DSPAM context");
    return NULL;
  }
  if (dspam_attach(ctx,dbh)) {
    PyErr_SetString(DspamError, "Failed to attach storage");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_detach__doc__[] =
"detach(dbh) -> None\n\
  Detach storage interface from context.";

static PyObject *
_dspam_detach(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  if (!PyArg_ParseTuple(args, ":detach")) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (dspam_detach(ctx)) {
    PyErr_SetString(DspamError, "Failed to detach storage");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_set_signature__doc__[] =
"set_signature(tag,sig) -> None\n\
  Store signature via storage driver by tag.";

static PyObject *
_dspam_set_signature(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  char *data;
  int len;
  const char *tag;
  struct _ds_spam_signature sig;
  if (!PyArg_ParseTuple(args, "ss#:set_signature",&tag,&data,&len)) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (!ctx->storage) {
    PyErr_SetString(DspamError, "Storage not attached to DSPAM context");
    return NULL;
  }
  sig.data = data;
  sig.length = len;
  if (_ds_set_signature(ctx,&sig,tag)) {
    PyErr_SetString(DspamError, "Failed to store signature");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_get_signature__doc__[] =
"get_signature(tag) -> None\n\
  Retrieve signature from storage driver by tag.";

static PyObject *
_dspam_get_signature(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  const char *tag;
  struct _ds_spam_signature sig;
  PyObject *o;
  if (!PyArg_ParseTuple(args, "s:get_signature",&tag)) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (!ctx->storage) {
    PyErr_SetString(DspamError, "Storage not attached to DSPAM context");
    return NULL;
  }
  sig.data = NULL;
  if (_ds_get_signature(ctx,&sig,tag)) {
    PyErr_SetString(DspamError, "Failed to retreive signature");
    return NULL;
  }
#if PY_MAJOR_VERSION >= 3
  o = PyByteArray_FromStringAndSize(sig.data,sig.length);
  if (!o) return NULL;
#else
  o = PyBuffer_New(sig.length);
  if (!o) return NULL;
  if (sig.length > 0) {
    void *data;
    Py_ssize_t dlen;
    if (PyObject_AsWriteBuffer(o,&data,&dlen)) {
      Py_DECREF(o);
      return NULL;
    }
    memcpy(data,sig.data,dlen);
  }
#endif
  return o;
}

static char _dspam_delete_signature__doc__[] =
"delete_signature(tag) -> None\n\
  Delete signature from storage driver by tag.";

static PyObject *
_dspam_delete_signature(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  const char *tag;
  if (!PyArg_ParseTuple(args, "s:delete_signature",&tag)) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (!ctx->storage) {
    PyErr_SetString(DspamError, "Storage not attached to DSPAM context");
    return NULL;
  }
  if (_ds_delete_signature(ctx,tag)) {
    PyErr_SetString(DspamError, "Failed to delete signature");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_verify_signature__doc__[] =
"verify_signature(tag) -> None\n\
  Return True if tag still stored via storage driver.";

static PyObject *
_dspam_verify_signature(PyObject *dspamctx, PyObject *args) {
  dspam_Object *self = (dspam_Object *)dspamctx;
  DSPAM_CTX *ctx = self->ctx;
  const char *tag;
  PyObject *o;
  if (!PyArg_ParseTuple(args, "s:verify_signature",&tag)) return NULL;
  if (!ctx) {
    PyErr_SetString(DspamError, "Uninitialized DSPAM context");
    return NULL;
  }
  if (!ctx->storage) {
    PyErr_SetString(DspamError, "Storage not attached to DSPAM context");
    return NULL;
  }
  o = _ds_verify_signature(ctx,tag) ? Py_False : Py_True;
  Py_INCREF(o);
  return o;
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
    PyErr_SetString(DspamError, "DSPAM context not active");
    return -1;
  }
  if (value == NULL) {
    sprintf(buf,"Cannot delete %s",name);
    PyErr_SetString(PyExc_TypeError, buf);
    return -1;
  }
#if PY_MAJOR_VERSION >= 3
  if (! PyLong_Check(value)) {
#else
  if (! PyInt_Check(value)) {
#endif
    sprintf(buf,"%s must be an int",name);
    PyErr_SetString(PyExc_TypeError, buf);
    return -1;
  }

#if PY_MAJOR_VERSION >= 3
  val = PyLong_AS_LONG(value);
#else
  val = PyInt_AS_LONG(value);
#endif
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

static PyObject *
_dspam_factors(dspam_Object *self, void *closure) {
  DSPAM_CTX *ctx = self->ctx;
  if (ctx && ctx->factors) {
    struct nt_c c_ft;
    PyObject *o = PyList_New(0);
    struct nt_node *node_ft = c_nt_first(ctx->factors, &c_ft);
    if (o == NULL) return NULL;
    while (node_ft != NULL) {
      struct dspam_factor *f = (struct dspam_factor *) node_ft->ptr;
      if (f) {
        PyObject *i = Py_BuildValue("(sf)",f->token_name,f->value);
	if (i == NULL) break;
        PyList_Append(o,i);
      }
      node_ft = c_nt_next(ctx->factors, &c_ft);
    }
    if (PyErr_Occurred()) {
      Py_DECREF(o);
      return NULL;
    }
    return o;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef dspamctx_methods[] = {
  { "addattribute", _dspam_addattribute, METH_VARARGS, _dspam_addattribute__doc__},
  { "clearattributes", _dspam_clearattributes, METH_VARARGS, _dspam_clearattributes__doc__},
  { "attach", _dspam_attach, METH_VARARGS, _dspam_attach__doc__},
  { "detach", _dspam_detach, METH_VARARGS, _dspam_detach__doc__},
  { "process", (PyCFunction)_dspam_process, METH_VARARGS|METH_KEYWORDS, _dspam_process__doc__},
  { "set_signature",_dspam_set_signature, METH_VARARGS, _dspam_set_signature__doc__},
  { "get_signature",_dspam_get_signature, METH_VARARGS, _dspam_get_signature__doc__},
  { "delete_signature",_dspam_delete_signature, METH_VARARGS, _dspam_delete_signature__doc__},
  { "verify_signature",_dspam_verify_signature, METH_VARARGS, _dspam_verify_signature__doc__},
  { "tokenize", _dspam_tokenize, METH_VARARGS, _dspam_tokenize__doc__},
  { "destroy", _dspam_destroy, METH_VARARGS, _dspam_destroy__doc__},
  { NULL, NULL }
};

static PyMemberDef dspamctx_members[] = {
  { "signature",T_OBJECT,offsetof(dspam_Object,sig),READONLY,
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
  { "totals", (getter)_dspam_gettot, NULL,
    "(SPAM,INNOCENT,MISS,FP,SPAMCORP,INNOCCORP,SPAMCLASS,INNOCCLASS)" },
  { "factors", (getter)_dspam_factors, NULL, "[(tok,weight),...]" },
  {NULL},
};

static char set_debug__doc__[] =
"set_debug(mode) -> None\n\
  Set debug mode.";

#ifndef DEBUG
static int DO_DEBUG = 0;
#endif

static PyObject *
set_debug(PyObject *self, PyObject *args) {
  int debug;
  if (!PyArg_ParseTuple(args, "i:set_debug",&debug)) return NULL;
  if (debug < 0 || debug > 2) {
    PyErr_SetString(DspamError, "set_debug: value out of range");
    return NULL;
  }
  DO_DEBUG = debug;
  Py_INCREF(Py_None);
  return Py_None;
}

static char set_verified_user__doc__[] =
"set_verified_user(flag) -> None\n\
  Set True if user is verified.";

static PyObject *
set_verified_user(PyObject *self, PyObject *args) {
  if (!PyArg_ParseTuple(args, "i:set_verified_user",&verified_user))
    return NULL;
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_userdir__doc__[] =
"userdir(home,user,ext) -> None\n\
  Return path of user specific filename.";

static PyObject *
_dspam_userdir(PyObject *dspamctx, PyObject *args) {
  const char *home = 0;
  const char *username = 0;
  const char *ext = 0;
  //char path[PATH_MAX];
  char path[256];
  if (!PyArg_ParseTuple(args, "ss|z:userdir", &home,&username,&ext))
  	return NULL;
  return Py_BuildValue("s",_ds_userdir_path(path,home,username,ext));
}

static char _dspam_get_fcntl_lock__doc__[] =
"get_fcntl_lock(fileno) -> None\n\
  Lock a file using the DSPAM locking protocol.";

static PyObject *
_dspam_get_fcntl_lock(PyObject *module, PyObject *args) {
  int fileno;
  if (!PyArg_ParseTuple(args, "i:get_fcntl_lock",&fileno)) return NULL;
  if (_ds_get_fcntl_lock(fileno)) {
    PyErr_SetString(DspamError, "Lock failed");
    return NULL;
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static char _dspam_free_fcntl_lock__doc__[] =
"free_fcntl_lock(fileno) -> None\n\
  Unlock a file locked with get_fcntl_lock().";

static PyObject *
_dspam_free_fcntl_lock(PyObject *module, PyObject *args) {
  int fileno;
  if (!PyArg_ParseTuple(args, "i:free_fcntl_unlock",&fileno)) return NULL;
  _ds_free_fcntl_lock(fileno);
  Py_INCREF(Py_None);
  return Py_None;
}

// static DRIVER_CTX DTX;

static char _libdspam_init__doc__[] =
"libdspam_init() -> None\n\
  Call once when your application starts.";

static PyObject *
_libdspam_init(PyObject *self, PyObject *args) {
  const char *driver = 0;
  if (!PyArg_ParseTuple(args, "z:init",&driver)) return NULL;
  if (libdspam_init(driver)) {
    PyErr_SetString(DspamError, "Unable to initialize libdspam");
    return NULL;
  }
  // FIXME: use &DTX after we figure out threading API
  dspam_init_driver(NULL);
  Py_INCREF(Py_None);
  return Py_None;
}

static char _libdspam_shutdown__doc__[] =
"libdspam_shutdown() -> None\n\
  Shutdown libdspam.";

static PyObject *
_libdspam_shutdown(PyObject *self, PyObject *args) {
  if (!PyArg_ParseTuple(args, ":shutdown")) return NULL;
  // FIXME: use &DTX after we figure out threading API
  dspam_shutdown_driver(NULL);
  libdspam_shutdown();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef _dspam_methods[] = {
  { "userdir", _dspam_userdir, METH_VARARGS, _dspam_userdir__doc__},
  { "get_fcntl_lock", _dspam_get_fcntl_lock, METH_VARARGS, _dspam_get_fcntl_lock__doc__},
  { "free_fcntl_lock", _dspam_free_fcntl_lock, METH_VARARGS, _dspam_free_fcntl_lock__doc__},
  { "set_debug",set_debug, METH_VARARGS, set_debug__doc__ },
  { "set_verified_user",set_verified_user, METH_VARARGS, set_verified_user__doc__ },
  { "libdspam_init",_libdspam_init, METH_VARARGS, _libdspam_init__doc__ },
  { "libdspam_shutdown",_libdspam_shutdown, METH_VARARGS, _libdspam_shutdown__doc__ },
  { NULL, NULL }
};

static PyTypeObject dspam_Type = {
#if PY_MAJOR_VERSION >= 3
  PyVarObject_HEAD_INIT(&PyType_Type,0)
  "dspam.ctx",
#else
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "dspam.ctx",
#endif
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
 	PyObject_Free,                 		/* tp_free */
};

static char _dspam_documentation[] =
"This module wraps the libdspam library API for the DSPAM Bayesian\n\
anti-spam package.\n";

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "dspam",           /* m_name */
    _dspam_documentation,/* m_doc */
    -1,                  /* m_size */
    _dspam_methods,      /* m_methods */
    NULL,                /* m_reload */
    NULL,                /* m_traverse */
    NULL,                /* m_clear */
    NULL,                /* m_free */
};

PyMODINIT_FUNC PyInit_dspam(void) {
    PyObject *m, *d;
 
   if (PyType_Ready(&dspam_Type) < 0)
          return NULL;

   m = PyModule_Create(&moduledef);
   if (m == NULL) return NULL;
#else
void
initdspam(void) {
   PyObject *m, *d;

   if (PyType_Ready(&dspam_Type) < 0) return;
   m = Py_InitModule4("dspam", _dspam_methods, _dspam_documentation,
		      (PyObject*)NULL, PYTHON_API_VERSION);
   if (m == NULL) return;
#endif
   d = PyModule_GetDict(m);
   if (PyDict_SetItemString(d,"LIBDSPAM_VERSION", Py_BuildValue("iii",
   	LIBDSPAM_VERSION_MAJOR,
   	LIBDSPAM_VERSION_MINOR,
   	LIBDSPAM_VERSION_PATCH))) goto initerror;
   DspamError = PyErr_NewException("dspam.error", PyExc_EnvironmentError, NULL);
   if (!DspamError) goto initerror;
   if (PyDict_SetItemString(d,"error", DspamError)) goto initerror;
   Py_INCREF(&dspam_Type);
   if (PyDict_SetItemString(d,"dspam", (PyObject *)&dspam_Type)) goto initerror;
   if (PyDict_SetItemString(d,"ctx", (PyObject *)&dspam_Type)) goto initerror;
   PyModule_AddStringMacro(m,CONFIGURE_ARGS);

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
   CONST(DST_NOTRAIN);
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
 initerror:
#if PY_MAJOR_VERSION >= 3
   return m;
#else
   return;
#endif
}
