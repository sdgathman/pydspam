#
# $Log$
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

from email.Encoders import encode_base64, encode_quopri

_seq = 0

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
  if msg.get_main_type() == 'text':
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
      if part.get_type() == 'text/html':
	any_html = True
	break
    # add tag to first suitable text segment
    done = False
    for part in msg.walk():
      if not part.is_multipart():
	if part.get_type() == 'text/html' \
	  or not any_html and part.get_main_type() == 'text':
	  _tag_part(part,sigkey)
	  done = True
	  break
    if not done:
      msg.epilog = "\n<!DSPAM:%s>\n\n" % sigkey

def extract_signature_tags(txt):
  tags = []
  beg = 0
  while True:
    beg = txt.find('<!DSPAM:',beg)
    if beg < 0: break
    beg += 8
    end = txt.find('>',beg)
    if end > beg and end - beg < 64:
      tags.append(txt[beg:end])
      beg -= 8
      txt = txt[:beg] + txt[end+1:]
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
	  groups.setdefault(user,[]).append(group)
	else:
	  groups[user] = group
    fp.close()
  except: pass
  return groups

def convert_eol(txt):
  txt = txt.splitlines()
  txt.append('')
  return '\n'.join(txt)

class DSpamDirectory(object):

  def _log(self,*msg): pass

  def __init__(self,userdir):
    self.userdir = userdir
    self.groupfile = os.path.join(userdir,'group')
    self.log = self._log

  def get_group(self,user):
    return parse_groups(self.groupfile).get(user,user)

  def user_files(self,user):
    "Return filenames for dict,sigs,mbox as a tuple."
    group = self.get_group(user)
    # find names of files
    dspam_userdir = self.userdir
    self.dspam_dict = os.path.join(dspam_userdir,group+'.dict')
    self.dspam_stats = os.path.join(dspam_userdir,group+'.stats')
    self.sigfile = os.path.join(dspam_userdir,user+'.sig')
    self.mbox = os.path.join(dspam_userdir,user+'.mbox')
    return (self.dspam_dict,self.sigfile,self.mbox)

# check spaminess for a message
  def check_spam(self,user,txt,recipients = None):
    "Return tagged message, or None if message was quarantined."

    dspam_dict,sigfile,mbox = self.user_files(user)

    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    savmask = os.umask(002) # mail group must be able write dict and sig
    try:
      ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
      txt = convert_eol(txt)
      ds.lock()
      try:
	ds.process(txt)
	self.totals = ds.totals
	self.probability = ds.probability
	try: print >>open(self.dspam_stats,'w'),"%d,%d,%d,%d" % ds.totals
	except: pass

	sigkey = put_signature(ds.signature,sigfile,ds.result)
	if not sigkey: return txt

	try:
	  # add signature key to message
	  msg = mime.MimeMessage(StringIO.StringIO(txt))
	  add_signature_tag(msg,sigkey,ds.probability)

	  # quarantine mail if dspam thinks it looks spammy
	  if ds.result == dspam.DSR_ISSPAM:
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
	except: pass

      finally:
	ds.unlock()
	ds.destroy()
    finally: os.umask(savmask)
    return txt

  def _feedback(self,user,txt,op):
    dspam_dict,sigfile,mbox = self.user_files(user)
    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    sig = None
    ds = dspam.dspam(dspam_dict,op,opts)
    try:
      ds.lock()
    except:
      # lock failed, queue for later
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
	    ds.process(sig)	# reverse stats
	    del db[tag]
	    try: print >>open(self.dspam_stats,'w'),"%d,%d,%d,%d" % ds.totals
	    except: pass
      finally:
	db.close()
    finally:
      ds.unlock()
    if not sig:	# no tags in sig database, use full text
      self.log('No tags: Adding body text as spam corpus.')
      opts = dspam.DSF_CHAINED|dspam.DSF_CORPUS|dspam.DSF_IGNOREHEADER
      if op == dspam.DSM_ADDSPAM:
	ds = dspam.dspam(dspam_dict,op,opts)
      else:
	ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
      txt = convert_eol(txt)
      ds.process(txt)
    self.totals = ds.totals
    # innoculate other users
    if sig:
      try:
	innoc_file = os.path.join(self.userdir,'innoculation')
	users = parse_groups(innoc_file,dups=True).get(user,[])
	opts = dspam.DSF_CORPUS|dspam.DSF_CHAINED|dspam.DSF_SIGNATURE
	for u in users:
	  self.log('INNOC:',u)
	  u_grp = self.get_group(u)
	  u_dict = os.path.join(self.userdir,u_grp+'.dict')
	  ds = dspam.dspam(u_dict,dspam.DSM_ADDSPAM,opts)
	  ds.process(sig)
      except Exception,x:
	self.log('FAIL:',x)
        # not critical if innoculation fails, so keep going
    return txt

  def add_spam(self,user,txt):
    "Report a message as spam."
    self.probability = 1.0
    self._feedback(user,txt,dspam.DSM_ADDSPAM)
    return None

  def false_positive(self,user,txt):
    "Report a false positive, return message with tags removed."
    self.probability = 0.0
    return self._feedback(user,txt,dspam.DSM_FALSEPOSITIVE)
