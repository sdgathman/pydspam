#
# $Log$
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
    # add signature key to message
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
    encode_base64(msg)

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

def parse_groups(groupfile):
  "Parse group file, return map from user -> group or none"
  groups = {}
  try:
    fp = open(groupfile,'r')
    for ln in fp.readlines():
      group,users = ln.strip().split(':',1)
      for user in users.split(','):
        groups[user] = group
    fp.close()
  except: pass
  return groups

def convert_eol(txt):
  txt = txt.splitlines()
  txt.append('')
  return '\n'.join(txt)

class DSpamDirectory(object):

  def __init__(self,userdir):
    self.userdir = userdir
    self.groupfile = os.path.join(userdir,'group')

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
    ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
    ds.lock()
    try:
      txt = convert_eol(txt)
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
    return txt

  def _feedback(self,user,txt,op):
    dspam_dict,sigfile,mbox = self.user_files(user)
    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    done = False
    ds = dspam.dspam(dspam_dict,op,opts)
    ds.lock()
    try:
      db = bsddb.btopen(sigfile,'c')
      try:
	txt,tags = extract_signature_tags(txt)
	for tag in tags:
	  if db.has_key(tag):
	    data = db[tag]
	    sig = data[4:]	# discard timestamp
	    rem = len(sig) % 8
	    if rem > 0: sig = sig[:-rem]	# discard status
	    ds.process(sig)	# reverse stats
	    del db[tag]
	    done = True
	    try: print >>open(self.dspam_stats,'w'),"%d,%d,%d,%d" % ds.totals
	    except: pass
      finally:
	db.close()
    finally:
      ds.unlock()
    if not done:	# no tags in sig database, use full text
      print 'No tags: Using full text'
      opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_IGNOREHEADER
      txt = convert_eol(txt)
      ds = dspam.dspam(dspam_dict,op,opts)
      ds.process(txt)
    self.totals = ds.totals
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
