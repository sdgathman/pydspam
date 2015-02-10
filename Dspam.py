#
# $Log$
# Revision 2.21.2.13  2009/08/28 03:20:31  customdesigned
# Process headers of redirected spam.
#
# Revision 2.21.2.12  2006/01/18 01:29:48  customdesigned
# passwd style update transaction lockfile
# case insensitive alerts
#
# Revision 2.21.2.11  2005/10/26 15:24:46  customdesigned
# Return message when forcing INNOCENT result
#
# Revision 2.21.2.10  2005/07/26 16:51:24  customdesigned
# Forced result option for honeypot.
#
# Revision 2.21.2.9  2005/06/14 15:00:06  customdesigned
# Work around tags mangled by quoted printable.  Sourceforge bug 1220391
#
# Revision 2.21.2.8  2005/06/06 15:43:28  stuart
# More python2.4 updates.
#
# Revision 2.21.2.7  2005/06/04 17:35:03  stuart
# Maintenance release 1.1.8
#
# Revision 2.21.2.6  2004/05/03 17:50:59  stuart
# handle spaces in innoculation list
#
# Revision 2.21.2.5  2004/04/08 23:29:58  stuart
# Handle tags within multiline HTML comment.
#
# Revision 2.21.2.4  2004/03/29 21:25:01  stuart
# Releasing _seq_lock in wrong finally
#
# Revision 2.21.2.3  2004/01/27 03:46:55  stuart
# dspam locking doesn't work right with multiple locks held in same process,
# so wrap dspam operations in mutex.
#
# Revision 2.22  2003/12/04 23:19:07  stuart
# Save dspam result.  Pass on exceptions when attempting to quarantine.
#
# Revision 2.21  2003/11/16 02:55:54  stuart
# Split libdspam and pydspam web pages.
#
# Revision 2.20  2003/11/09 00:30:36  stuart
# Queue large messages for delayed processing.
#
# Revision 2.19  2003/11/01 18:53:17  stuart
# Strip nulls from incoming messages
#
# Revision 2.18  2003/10/28 01:05:59  stuart
# Innoculate with all signatures found
#
# Revision 2.17  2003/10/22 20:54:49  stuart
# Properly teach false positives.
#
# Revision 2.16  2003/10/22 05:30:43  stuart
# Support screening with classify flag to check_spam
#
# Revision 2.15  2003/10/22 01:55:10  stuart
# Log and ignore innoculation errors.
#
# Revision 2.14  2003/10/16 22:21:15  stuart
# Code and test innoculations.  When a message is reported as spam,
# add as a spam corpus to those who want it.
#
# Revision 2.13  2003/10/16 16:25:16  stuart
# Test for and fix tag not being found in base64 encoded segments.
# We fix by reencoding as quoted printable.
#
# Revision 2.12  2003/10/16 02:18:03  stuart
# Support for queueing addspams which get a lock timeout.
#
# Revision 2.11  2003/09/30 21:06:52  stuart
# Use umask to create files with proper permissions.
#
# Revision 2.10  2003/09/06 07:09:38  stuart
# Option to save recipients in quarantined message.
#
# Revision 2.9  2003/09/06 05:17:35  stuart
# Update text format stats used by CGI script.
#
# Revision 2.8  2003/09/06 05:05:22  stuart
# Modify API to:
# o record recipients in quarantine
# o return message with tags removed for false_positive
#
# Revision 2.7  2003/09/01 19:34:18  stuart
# Tagging nits.
#
# Revision 2.6  2003/09/01 18:59:48  stuart
# Add convert_eol function.
#
# Revision 2.5  2003/09/01 18:00:18  stuart
# False positives needed dspam tagging.
#
# Revision 2.4  2003/09/01 15:30:10  stuart
# Unittest quarantine
#
# Revision 2.3  2003/08/30 20:24:30  stuart
# Unit test high level Dspam
#
# Revision 2.2  2003/08/30 05:42:53  stuart
# Feedback methods
#
# Revision 2.1  2003/08/30 04:46:57  stuart
# Begin higher level framework: signature database and quarantine mbox
#
#

import os
import time
import dspam
import bsddb
import random
import struct
# the email package is buggy handling message attachments, so
# use the mime package from milter instead
import mime
import StringIO
import thread

from email.Encoders import encode_base64, encode_quopri
from contextlib import contextmanager

VERSION = "1.3" # abi compatibility, not package version

_seq_lock = thread.allocate_lock()
_seq = 0

@contextmanager 
def file_lock(fname):
  with open(fname,'a') as fp:
    dspam.get_fcntl_lock(fp.fileno())
    yield
    dspam.free_fcntl_lock(fp.fileno())

def create_signature_id():
  global _seq
  _seq += 1
  r = random.randint(0,999999)
  return "%X%d%d%d"%(long(time.time()*1000),os.getpid(),_seq,r)

def put_signature(sig,sigfile,status):
  db = bsddb.btopen(sigfile,'c')
  try:
    key = create_signature_id()
    while db.has_key(key):
      key = create_signature_id()
    data = struct.pack('l',time.time()) + str(sig) + chr(status)
    db[key] = data
  except:
    key = None
  db.close()
  return key

# add tag to a non-multipart message
def _tag_part(msg,sigkey):
  assert not msg.is_multipart()
  tag = "\n<!DSPAM:%s>\n\n" % sigkey
  cte = msg.get('content-transfer-encoding', '').lower()
  recode = cte == 'base64'
  txt = msg.get_payload(decode=recode)
  if msg.get_content_maintype() == 'text':
      if not txt.endswith('\n'):
	tag = '\n' + tag
      if txt.rstrip().lower().endswith("</html"):
	tag = '>' + tag
  msg.set_payload(txt + tag)
  if recode:
    del msg["content-transfer-encoding"]
    encode_quopri(msg)

def add_signature_tag(msg,sigkey,prob=None):
  # add signature key to message
  if not prob == None:
    msg['X-DSpam-Score'] = '%f'%prob
  if not msg.is_multipart():
    _tag_part(msg,sigkey)
  else:
    # check whether any explicit html
    any_html = False
    for part in msg.walk():
      if not part.is_multipart() and part.get_content_type() == 'text/html':
	any_html = True
	break
    # add tag to first suitable text segment
    for part in msg.walk():
      if not part.is_multipart():
	if part.get_content_type() == 'text/html' or not any_html and (
	    part.get_content_maintype() == 'text' or not part.get_content_maintype()):
	  _tag_part(part,sigkey)
	  break
    else:
      msg.epilogue = "\n\n<!DSPAM:%s>\n\n" % sigkey

def extract_signature_tags(txt):
  tags = []
  beg = 0
  while True:
    nbeg = txt.find('<!DSPAM:',beg)
    if nbeg < 0:
      nbeg = txt.find('<!--DSPAM:',beg)
      if nbeg < 0: break
      offset = 10
      endpat = '-->'
    else:
      offset = 8
      endpat = '>'
    beg = nbeg + offset
    end = txt.find(endpat,beg)
    if end > beg and end - beg < 64:
      tags.append(txt[beg:end].replace('=\r\n',''))
      beg -= offset
      txt = txt[:beg] + txt[end+len(endpat):]
  return (txt,tags)

def parse_groups(groupfile,dups=False):
  "Parse group file, return map from user -> group or none"
  groups = {}
  try:
    fp = open(groupfile,'r')
    for ln in fp.readlines():
      group,users = ln.strip().split(':',1)
      for user in users.split(','):
        if dups:
	  groups.setdefault(user.strip(),[]).append(group)
	else:
	  groups[user.strip()] = group
    fp.close()
  except: pass
  return groups

def convert_eol(txt):
  txt = txt.splitlines()
  txt.append('')
  return '\n'.join(txt).replace('\x00','')

class DSpamDirectory(object):

  def _lognull(self,*msg): pass

  def __init__(self,userdir):
    ## DSPAM home.  Base directory where dspam stores
    # dictionaries and configs.
    self.userdir = userdir
    self.groupfile = os.path.join(userdir,'group')
    ## Logging method.
    self.log = self._lognull
    self.headerchange = None

  ## Return group user belongs to.  
  # FIXME: update for new group concepts.
  def get_group(self,user):
    return parse_groups(self.groupfile).get(user,user)

  def user_files(self,user):
    "Return filenames for dict,sigs,mbox as a tuple."
    group = self.get_group(user)
    # find names of files
    self.dspam_dict = dspam.userdir(self.userdir,group,'.css')
    self.dspam_stats = dspam.userdir(self.userdir,group,'.stats')
    self.sigfile = dspam.userdir(self.userdir,user,'.sig')
    self.mbox = dspam.userdir(self.userdir,user,'.mbox')
    return (self.dspam_dict,self.sigfile,self.mbox)

# check spaminess for a message
  def check_spam(self,user,txt,recipients = None,
  	classify=False,quarantine=True,force_result=None):
    "Return tagged message, or None if message was quarantined."

    dspam_dict,sigfile,mbox = self.user_files(user)

    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    if classify:
      op = dspam.DSM_CLASSIFY
    else:
      op = dspam.DSM_PROCESS
    savmask = os.umask(006) # mail group must be able write dict and sig
    try:
      _seq_lock.acquire()	# for drivers that aren't thread safe
      ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
      #with file_lock(dspam_dict):
      dspam.file_lock(dspam_dict)
      txt = convert_eol(txt)
      try:
	ds.process(txt)
	self.totals = ds.totals
	self.probability = ds.probability
	self.result = ds.result

	sig = ds.signature
	if classify:
	  if self.result == dspam.DSR_ISINNOCENT: return txt
	  if not quarantine: return None
	  opts &= ~dspam.DSF_CLASSIFY
	  ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
	  ds.process(txt) # result should be same since dict is locked
	  if ds.result != dspam.DSR_ISSPAM:
	    self.log("WARN: classification changed")
	    sig = ds.signature
	    ds = dspam.dspam(dspam_dict,dspam.DSM_ADDSPAM,opts)
	    ds.process(sig) # force back to SPAM
	elif force_result == dspam.DSR_ISSPAM:
	  if ds.result != dspam.DSR_ISSPAM:
	    ds = dspam.dspam(dspam_dict,dspam.DSM_ADDSPAM,opts)
	    ds.process(sig) # force back to SPAM
	    self.result = force_result
	  self.innoc(user,[sig],force_result)
	  if not quarantine: return None
	elif force_result == dspam.DSR_ISINNOCENT:
	  if ds.result != dspam.DSR_ISINNOCENT:
	    ds = dspam.dspam(dspam_dict,dspam.DSM_FALSEPOSITIVE,opts)
	    ds.process(sig) # force back to INNOCENT
	    self.result = force_result
	  self.innoc(user,[sig],force_result)

	self.totals = ds.totals
	try: print >>open(self.dspam_stats,'w'),"%d,%d,%d,%d" % ds.totals
	except: pass
	sigkey = put_signature(sig,sigfile,self.result)
	if not sigkey:
	  self.log("WARN: tag generation failed")
	  return txt

	try:
	  # add signature key to message
	  msg = mime.message_from_file(StringIO.StringIO(txt))
	  msg.headerchange = self.headerchange
	  add_signature_tag(msg,sigkey,self.probability)
	  # quarantine mail if dspam thinks it looks spammy
	  if self.result == dspam.DSR_ISSPAM:
	    del msg['X-Dspam-Recipients']
	    if recipients:
	      msg['X-Dspam-Recipients'] = ', '.join(recipients)
	    txt = msg.as_string()
	    fp = open(mbox,'a')
	    if not txt.startswith('From '):
	      fp.write('From dspam %s\n' % time.ctime())
	    fp.write(txt)
	    fp.close()
	    return None
	  txt = msg.as_string()
	except:
	  if True or self.result == dspam.DSR_ISSPAM: raise

      finally:
	dspam.file_unlock(dspam_dict)
	ds.destroy()
    finally:
      _seq_lock.release()
      os.umask(savmask)
    return txt

  def _feedback(self,user,txt,op):
    dspam_dict,sigfile,mbox = self.user_files(user)
    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    sig = None
    sigs = []
    queue = False
    #if len(txt) > 500000:
    #  queue = True
    if not queue:
      ds = dspam.dspam(dspam_dict,op,opts)
      try:
	ds.lock()
      except:
	queue = True # lock failed, queue for later
    if queue:
      # queue for later
      if not txt.startswith('From '):
        txt = 'From %s %s\n' % (user,time.ctime()) + txt
      if op == dspam.DSM_ADDSPAM:
	log = os.path.join(self.userdir,user+'.spam')
      else:
	log = os.path.join(self.userdir,user+'.fp')
      fp = open(log,'a')
      fp.write(txt)
      fp.close()
      if op != dspam.DSM_ADDSPAM:
        # strip tags before forwarding on to user
	txt,tags = extract_signature_tags(txt)
      return txt
    try:
      db = bsddb.btopen(sigfile,'c')
      try:
	txt,tags = extract_signature_tags(txt)
	for tag in tags:
	  self.log("TAG:",tag);
	  if db.has_key(tag):
	    data = db[tag]
	    sig = data[4:]	# discard timestamp
	    rem = len(sig) % 8
	    if rem > 0: 
	      status = sig[-rem:]
	      sig = sig[:-rem]
	    else:
	      status = ''
	    sigs.append(sig)
	    ds.process(sig)	# reverse stats
	    del db[tag]
	    try: print >>open(self.dspam_stats,'w'),"%d,%d,%d,%d" % ds.totals
	    except: pass
      finally:
	db.close()
    finally:
      ds.unlock()
    if not sig:	# no tags in sig database, use full text
      self.log('No tags: Adding body text as corpus.')
      opts = dspam.DSF_CHAINED|dspam.DSF_CORPUS
      if op == dspam.DSM_ADDSPAM:
	ds = dspam.dspam(dspam_dict,op,opts)
      else:
	ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
      txt = convert_eol(txt)
      msg = mime.message_from_file(StringIO.StringIO(txt))
      del msg['Resent-Date']
      del msg['Resent-From']
      del msg['Resent-To']
      del msg['Resent-Subject']
      ds.process(msg.as_string())
      sig = ds.signature
      if sig: sigs.append(sig)
    self.totals = ds.totals
    # innoculate other users who requested it
    self.innoc(user,sigs,op)
    return txt

  def innoc(self,user,sigs,op):
    if sigs:
      try:
	innoc_file = os.path.join(self.userdir,'innoculation')
	users = parse_groups(innoc_file,dups=True).get(user,[])
	opts = dspam.DSF_CORPUS|dspam.DSF_CHAINED|dspam.DSF_SIGNATURE
	for u in users:
	  self.log('INNOC:',u)
	  u_grp = self.get_group(u)
	  u_dict = os.path.join(self.userdir,u_grp+'.dict')
	  ds = dspam.dspam(u_dict,op,opts)
	  for sig in sigs:
	    ds.process(sig)
      except Exception,x:
	self.log('FAIL:',x)
        # not critical if innoculation fails, so keep going

  def add_spam(self,user,txt):
    "Report a message as spam."
    self.probability = 1.0
    _seq_lock.acquire()
    try:
      self._feedback(user,txt,dspam.DSM_ADDSPAM)
    finally:
      _seq_lock.release()
    return None

  def false_positive(self,user,txt):
    "Report a false positive, return message with tags removed."
    self.probability = 0.0
    _seq_lock.acquire()
    try:
      return self._feedback(user,txt,dspam.DSM_FALSEPOSITIVE)
    finally:
      _seq_lock.release()
