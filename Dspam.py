#
# $Log$
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
    data = struct.pack('l',time.time()) + sig + chr(status)
    db[key] = data
    # add signature key to message
  except:
    key = None
  db.close()
  return key

# add tag to a non-multipart message
def add_signature_tag(msg,sigkey):
  assert not msg.is_multipart()
  tag = "\n<!DSPAM:%s>\n\n" % sigkey
  cte = msg.get('content-transfer-encoding', '').lower()
  recode = cte == 'base64'
  txt = msg.get_payload(decode=recode)
  if msg.get_main_type() == 'text':
    if txt.strip().lower().endswith("</html"):
      tag = '>' + tag
  msg.set_payload(txt + tag)
  if recode:
    del msg["content-transfer-encoding"]
    encode_base64(msg)

def extract_signature_tags(txt):
  pass

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

class DSpamDirectory(object):

  def __init__(self,userdir):
    self.userdir = userdir
    self.groupfile = os.path.join(userdir,'group')

# check spaminess for a message
  def check_spam(self,user,txt):
    "Return tagged message, or None if message was quarantined."
    group = parse_groups(self.groupfile).get(user,user)

    # find names of files
    dspam_userdir = self.userdir
    dspam_dict = os.path.join(dspam_userdir,group+'.dict')
    sigfile = os.path.join(dspam_userdir,user+'.sig')
    mbox = os.path.join(dspam_userdir,user+'.mbox')

    opts = dspam.DSF_CHAINED|dspam.DSF_SIGNATURE|dspam.DSF_NOLOCK
    ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,opts)
    ds.lock()
    try:
      txt = '\n'.join(txt.splitlines())+'\n' # convert to unix EOL
      ds.process(txt)
      # quarantine mail if dspam thinks it looks spammy
      if ds.result == dspam.DSR_ISSPAM:
	try:
	  fp = open(mbox,'a')
	  fp.write(txt)
	  fp.close()
	  return None
	except: pass
      # if apparently innocent, or quarantine failes, save signature in db
      sigkey = put_signature(ds.signature,sigfile,ds.result)
      prob = ds.probability
    finally:
      ds.unlock()
      ds.destroy()

      # add signature key to message
      fp = StringIO.StringIO(txt)
      msg = mime.MimeMessage(fp)
      del fp
      msg['X-DSpam-Score'] = '%f'%prob
      if not msg.is_multipart():
        add_signature_tag(msg,sigkey)
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
	      add_signature_tag(part,sigkey)
	      done = True
	      break
	if not done:
	  msg.epilog = "\n<!DSPAM:%s>\n\n" % sigkey
      return msg.as_string()

  # report a message as spam
  def add_spam(self,user,txt):
    pass

  def false_positive(self,user,txt):
    pass
