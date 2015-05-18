#
# $Log$
# Revision 2.36  2015/05/18 01:39:33  customdesigned
# Add PKGLIBDIR
#
# Revision 2.35  2015/05/18 01:11:11  customdesigned
# Use --libdir CONFIGURE_ARG to compute driver dir.
#
# Revision 2.34  2015/02/16 00:02:42  customdesigned
# Doc updates.
#
# Revision 2.33  2015/02/15 22:49:46  customdesigned
# Another classify typo fixed
#
# Revision 2.32  2015/02/15 22:23:25  customdesigned
# Fix packaging bugs.
#
# Revision 2.31  2015/02/15 18:34:14  customdesigned
# More fixes from production testing.
#
# Revision 2.30  2015/02/15 05:36:24  customdesigned
# Fix classify=True, update selinux policy to match epel dspam-3.10.2 package.
#
# Revision 2.29  2015/02/14 22:40:53  customdesigned
# Initial 3.10 test
#
# Revision 2.28  2015/02/14 21:38:13  customdesigned
# Passes test suite.
#
# Revision 2.27  2015/02/14 21:14:47  customdesigned
# Much farther through test suite.
#
# Revision 2.26  2015/02/14 18:55:04  customdesigned
# Add set_verified_user method
#
# Revision 2.25  2015/02/14 15:40:10  customdesigned
# Crasher typo fixed.
#
# Revision 2.24  2015/02/14 02:24:14  customdesigned
# Finished revamping Dspam.py, gets past initialization, then segfaults.  :-(
#
# Revision 2.23  2015/02/11 22:06:03  customdesigned
# Merge pydspam-3-branch to trunk
#
# Revision 2.21.2.13.2.1  2015/02/10 00:06:39  customdesigned
# Add *_fcntl_lock and get/set/delete/verify signature.
#
#

## @package Dspam
# A high level framework for using dspam from a python application.
#
# The Dspam module currently hardwires the "hash" storage driver.  This driver
# generally requires that your application have an effective group id of
# "mail", and have a umask that will allow other applications in the mail group
# read/write/execute access.
#

import os
import time
import dspam
import bsddb
import random
import struct
import urllib
# the email package is buggy handling message attachments, so
# use the mime package from milter instead
import mime
import StringIO
import thread

from email.Encoders import encode_base64, encode_quopri
from contextlib import contextmanager

def _configure_dict():
  a = dspam.CONFIGURE_ARGS.split("' '")
  if a[0].startswith(" '"): a[0] = a[0][2:]
  if a[-1].endswith("'"): a[-1] = a[-1][:-1]
  d = {}
  for s in a:
    t = s.split('=',1)
    k = t[0]
    if len(t) == 1:
      d[k] = True
    else:
      d[k] = t[1]
  return d

## Arguments passed to configure when building libdspam as a dict.
# Flag arguments are mapped to True.
# @see dspam.CONFIGURE_ARGS
# @since 1.3.1
CONFIGURE_ARGS = _configure_dict()

## The directory where package specific dynamic libraries are stored.
# This includes drivers and plugins.
# @since 1.3.1
PKGLIBDIR = os.path.join(CONFIGURE_ARGS['--libdir'],'dspam')

dspam.libdspam_init(os.path.join(PKGLIBDIR,'libhash_drv.so'))

VERSION = "1.3.1" # abi compatibility, not package version

_seq_lock = thread.allocate_lock()
_seq = 0

@contextmanager 
def file_lock(fname):
  with open(fname,'a') as fp:
    dspam.get_fcntl_lock(fp.fileno())
    yield fp
    dspam.free_fcntl_lock(fp.fileno())

## Create a mostly unique tag for a signature.
def create_signature_id():
  global _seq
  _seq += 1
  r = random.randint(0,999999)
  return "%X%d%d%d"%(long(time.time()*1000),os.getpid(),_seq,r)

## Add signature to database.  By default, use the signature database
# provided by the dspam database driver.  If sigfile is supplied,
# it is a bsdddb database that we manage ourselves (including purging
# old entries, since dspam no longer does that).  I suspect we do not
# really need the bsddb option, but it is there for now.
# @param ds the dspam.ctx 
# @param sig the signature from the dspam.ctx
# @param sigfile if given, a bsddb database to use instead of the dspam driver
def put_signature(ds,sig,sigfile=None):
  if sigfile:
    db = bsddb.btopen(sigfile,'c')
    try:
      key = create_signature_id()
      while db.has_key(key):
	key = create_signature_id()
      data = struct.pack('l',time.time()) + str(sig)
      db[key] = data
    except:
      key = None
    db.close()
  else:
    try:
      key = create_signature_id()
      while ds.verify_signature(key):
	key = create_signature_id()
      ds.set_signature(key,sig)
    except Exception,x:
      #print 'put_signature:',x
      key = None
  return key

## Add tag to a non-multipart message.
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

## Add DSPAM tag to message. We do this the old htmlish way.
# @param msg the original message to tag
# @param sigkey the signature tag
# @param prob probability for X-Dspam-Score header field if supplied
# @param factors factors for X-Dspam-Factors header field if supplied
def add_signature_tag(msg,sigkey,prob=None,factors=None):
  # add signature key to message
  if not prob == None:
    msg['X-DSpam-Score'] = '%2.5f'%prob
  if not factors == None:
    t = ['%d'%len(factors)]
    for tok,val in factors:
      t.append('%s,%2.5f'%(urllib.quote(tok),val))
    msg['X-DSpam-Factors'] = '\n\t'.join(t)
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

## Extract all DSPAM tags from a message.
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

## Parse old group file.  This version parses the old dspam-2.6 group file,
# which we will keep around a while for compatibility.
# Syntax is very simple:
# <pre>
# group1: user1,user2
# group2: user1,user3,user4
# </pre>
# returns the map:
# <pre>
# { 'user1': ['group1','group2'],
#   'user2': ['group1'],
#   'user3': ['group2'],
#   'user4': ['group2'] }
# </pre>
def parse_groups(groupfile,dups=False):
  "Parse group file, return map from user -> [group ...]"
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

## Convert message to unix end of line conventions.
# @param txt the original message
# @return the message with '\n' as line separator
def convert_eol(txt):
  txt = txt.splitlines()
  txt.append('')
  return '\n'.join(txt).replace('\x00','')

## Operations on the DSPAM directory.
class DSpamDirectory(object):

  def _lognull(self,*msg): pass

  ## Initialize DSpamDirectory.  The base directory is something like
  # <code>/var/lib/dspam</code>.
  # @param userdir the DSPAM base directory
  def __init__(self,userdir):
    ## DSPAM home.  Base directory where dspam stores dictionaries and configs.
    self.userdir = userdir
    ## Path of group definition file.  Note, syntax has changed since dspam-2.6.
    self.groupfile = os.path.join(userdir,'group')
    ## Logging method.
    self.log = self._lognull
    ## Hook for changing mail headers in the MTA to mirror changes by Dspam.
    # See mime module from pymilter for details.
    self.headerchange = None
    ## The dspam user current being processed
    self.username = None
    ## The spam score from 0.0 to 1.0
    self.probability = 0.0
    ## The top tokens that determined the spam score.
    self.factors = []
    ## Default spam score algorithms to use.
    self.algorithms = dspam.DSA_GRAHAM|dspam.DSP_GRAHAM|dspam.DSA_BURTON
    ## Default tokenizer
    self.tokenizer = dspam.DSZ_CHAIN
    ## Training mode.  Default to train on everything, since
    # that is what old dspam did, and milter depends on that.
    self.training = dspam.DST_TEFT
    ## DSPAM totals for user from last operation.
    self.totals = (0,0,0,0,0,0,0,0)
    ## Classification from last check_spam.
    self.result = dspam.DSR_NONE
    ## Path of quarantine mailbox used by pydspam for user.
    # The dspam LDA and other libdspam clients may have different
    # quarantines.
    self.mbox = None
    ## Path of lock file used by libdspam.
    # @see dspam.get_fcntl_lock
    self.lock = None

  ## Create dspam.ctx using configured defaults. 
  # E.g.
  # <pre>
  # with self.dspam_ctx(dspam.DSM_CLASSIFY) as ds:
  #   ds.process(txt)
  #   self.result = ds.result
  # </pre>
  # @param op dspam operation mode: one of dspam.DSM_*
  # @param flags dspam operation flags: set of dspam.DSF_*
  # @param user a different user, e.g. for innoculation
  # @return context manager for dspam.ctx
  @contextmanager
  def dspam_ctx(self,op,flags=0,user=None):
    if not user:
      user = self.username
    ds = dspam.ctx(user,op,flags,home=self.userdir)
    ds.algorithms = self.algorithms
    ds.tokenizer = self.tokenizer
    ds.training_mode = self.training
    ds.attach()
    yield ds
    if user == self.username:
      self.totals = ds.totals
    ds.destroy()

  ## Return group user belongs to.  
  # FIXME: update for new group concepts and syntax.
  def get_group(self,user):
    return parse_groups(self.groupfile).get(user,user)

  ## Set username and return common pathnames.
  # @param user The dspam user for subsequent operations.
  # @return commonly used pathnames: (dspam_dict,sigfile,mbox)
  def user_files(self,user):
    "Return filenames for dict,sigs,mbox as a tuple."
    group = self.get_group(user)
    # find names of files
    self.username = user
    try: os.makedirs(dspam.userdir(self.userdir,user))
    except: pass
    #self.group = group
    self.dspam_dict = dspam.userdir(self.userdir,group,'css')
    self.dspam_stats = dspam.userdir(self.userdir,group,'stats')
    self.sigfile = dspam.userdir(self.userdir,user,'sig')
    self.mbox = dspam.userdir(self.userdir,user,'mbox')
    self.lock = dspam.userdir(self.userdir,user,'lock')
    return (self.dspam_dict,self.sigfile,self.mbox)

  ## Check spaminess of a message.
  # 
  # @param user	the dspam user (email account)
  # @param txt	the message as collected from the MTA
  # @param recipients	If provided, a list of recipients to record in 
  #	quarantined messages to assist later delivery.
  # @param classify	
  # @param quarantine	Add messages classified as spam to mbox quarantine
  #	if true.
  # @param force_result	train as this result
  # @return tagged message, or None if message was quarantined
  def check_spam(self,user,txt,recipients = None,
  	classify=False,quarantine=True,force_result=None):
    "Return tagged message, or None if message was quarantined."

    dspam_dict,sigfile,mbox = self.user_files(user)

    savmask = os.umask(006) # mail group must be able write dict and sig
    try:
      _seq_lock.acquire()	# for drivers that aren't thread safe
      txt = convert_eol(txt)
      with file_lock(self.lock):
	if classify:
	  op = dspam.DSM_CLASSIFY
	else:
	  op = dspam.DSM_PROCESS
	with self.dspam_ctx(op,dspam.DSF_SIGNATURE) as ds:
	  ds.process(txt)
	  self.probability = ds.probability
	  self.result = ds.result
	  self.factors = ds.factors
	  sig = ds.signature
	if classify:
	  if self.result == dspam.DSR_ISINNOCENT: return txt
	  if not quarantine: return None
	  with self.dspam_ctx(dspam.DSM_PROCESS,dspam.DSF_SIGNATURE) as ds:
	    ds.process(txt)
	    self.probability = ds.probability
	    self.result = ds.result
	    self.factors = ds.factors
	    sig = ds.signature
	elif force_result == dspam.DSR_ISSPAM:
	  if self.result != dspam.DSR_ISSPAM:
	    with self.dspam_ctx(dspam.DSM_PROCESS,dspam.DSF_SIGNATURE) as ds:
	      ds.classification = dspam.DSR_ISSPAM
	      ds.source = dspam.DSS_ERROR
	      ds.process(None,sig=sig) # force back to SPAM
	    self.result = force_result
	  self._innoc(user,[sig],force_result)
	  if not quarantine: return None
	elif force_result == dspam.DSR_ISINNOCENT:
	  if self.result != dspam.DSR_ISINNOCENT:
	    with self.dspam_ctx(dspam.DSM_PROCESS,dspam.DSF_SIGNATURE) as ds:
	      ds.classification = dspam.DSR_ISINNOCENT
	      ds.source = dspam.DSS_ERROR
	      ds.process(None,sig=sig) # force back to INNOCENT
	    self.result = force_result
	  self._innoc(user,[sig],force_result)

	return self._add_sig(txt,sig,recipients)
    finally:
      _seq_lock.release()
      os.umask(savmask)

  ## Add signature key to message, and quarantine if spammy.
  # The results of the last check_spam as used.
  # @param txt the message
  # @param sig the signature
  # @param recipients list of recipients for later delivery
  def _add_sig(self,txt,sig,recipients=None):
    with self.dspam_ctx(dspam.DSM_TOOLS) as ds:
      self.write_web_stats(ds.totals)
      sigkey = put_signature(ds,sig)
    if not sigkey:
      self.log("WARN: tag generation failed")
      return txt
    try:
      # add signature key to message
      msg = mime.message_from_file(StringIO.StringIO(txt))
      msg.headerchange = self.headerchange
      add_signature_tag(msg,sigkey,self.probability,self.factors)
      # quarantine mail if dspam thinks it looks spammy
      if self.result == dspam.DSR_ISSPAM:
	del msg['X-Dspam-Recipients']
	if recipients:
	  msg['X-Dspam-Recipients'] = ', '.join(recipients)
	txt = msg.as_string()
	with open(self.mbox,'a') as fp:
	  if not txt.startswith('From '):
	    fp.write('From dspam %s\n' % time.ctime())
	  fp.write(txt)
	return None
      txt = msg.as_string()
    except:
      if True or self.result == dspam.DSR_ISSPAM: raise
    return txt

  ## Update dspam stats stored as text for the web interface.
  # @param totals totals obtained from dspam.ctx.totals
  def write_web_stats(self,totals):
    ( spam_learned,innocent_learned,
      spam_misclassified,innocent_misclassified,
      spam_corpusfed,innocent_corpusfed,
      spam_classified,innocent_classified) = totals
    with open(self.dspam_stats,'w') as fp:
      fp.write("%d,%d,%d,%d,%d,%d\n" % (
	 max(0, (spam_learned + spam_classified) -
	   (spam_misclassified + spam_corpusfed)),
	 max(0, (innocent_learned + innocent_classified) -
	   (innocent_misclassified + innocent_corpusfed)),
	 spam_misclassified, innocent_misclassified,
	 spam_corpusfed, innocent_corpusfed))

  def _feedback(self,user,txt,op,queue=False):
    #if len(txt) > 500000:
    #  queue = True
    if queue:
      # queue for later
      if not txt.startswith('From '):
        txt = 'From %s %s\n' % (user,time.ctime()) + txt
      if op == dspam.DSR_ISSPAM:
	log = dspam.userdir(self.userdir,user,'spam')
      else:
	log = dspam.userdir(self.userdir,user,'fp')
      with open(log,'a') as fp:
	fp.write(txt)
      if op != dspam.DSR_ISSPAM:
        # strip tags before forwarding on to user
	txt,tags = extract_signature_tags(txt)
      return txt
    dspam_dict,sigfile,mbox = self.user_files(user)
    sig = None
    sigs = []
    try:
      with self.dspam_ctx(dspam.DSM_PROCESS,dspam.DSF_SIGNATURE) as ds:
	txt,tags = extract_signature_tags(txt)
	for tag in tags:
	  if ds.verify_signature(tag):
	    self.log('reverse tag',tag)
	    sig = ds.get_signature(tag)
	    sigs.append(sig)
	    ds.classification = op
	    ds.source = dspam.DSS_ERROR
	    ds.process(None,sig=sig)	# reverse stats
	    ds.delete_signature(tag)
      try: 
	self.write_web_stats(self.totals)
      except: pass
      if not sig:	# no tags in sig database, use full text
	self.log('No tags: Adding body text as corpus.')
	with self.dspam_ctx(dspam.DSM_PROCESS) as ds:
	  ds.classification = op
	  ds.source = dspam.DSS_CORPUS
	  ds.addattribute("IgnoreHeader","Resent-Date")
	  ds.addattribute("IgnoreHeader","Resent-From")
	  ds.addattribute("IgnoreHeader","Resent-To")
	  ds.addattribute("IgnoreHeader","Resent-Subject")
	  ds.process(convert_eol(txt))
	  sig = ds.signature
	  if sig: sigs.append(sig)
      # innoculate other users who requested it
      self._innoc(user,sigs,op)
      return txt
    except Exception,x:
      # failed, queue for later
      self.log('feedback:',x)
      self._feedback(user,txt,op,queue=True)

  def _innoc(self,user,sigs,op):
    if sigs:
      try:
	innoc_file = os.path.join(self.userdir,'innoculation')
	users = parse_groups(innoc_file,dups=True).get(user,[])
	for u in users:
	  self.log('INNOC:',u)
	  u_grp = self.get_group(u)
	  with self.dspam_ctx(dspam.DSM_PROCESS,dspam.DSF_SIGNATURE,u) as ds:
	    ds.classification = op
	    ds.source = dspam.DSS_INOCULATION
	    for sig in sigs:
	      ds.process(None,sig=sig)
      except Exception,x:
	self.log('FAIL:',x)
        # not critical if innoculation fails, so keep going

  ## Report a false negative.  Tell DSPAM a message it though was innocent
  # is actually spam.  DSPAM looks for signature keys, and looks up
  # stored signatures with them.  It trains DSPAM with the signature,
  # setting the source to DSS_ERROR.  If no signature is found, it adds the
  # spam as a spam "corpus".
  # @param user the DSPAM user 
  # @param txt the spam message
  def add_spam(self,user,txt):
    "Report a message as spam."
    self.probability = 1.0
    _seq_lock.acquire()
    try:
      return self._feedback(user,txt,dspam.DSR_ISSPAM)
    finally:
      _seq_lock.release()
    return None

  ## Report a false positive.  Tell DSPAM a message it though was spam
  # is actually innocent.  DSPAM looks for signature keys, and looks up
  # stored signatures with them.  It trains DSPAM with the signature,
  # setting the source to DSS_ERROR.  If no signature is found, it adds the
  # message as an innocent "corpus" (DSS_CORPUS).
  # @param user the DSPAM user 
  # @param txt the innocent message
  def false_positive(self,user,txt):
    "Report a false positive, return message with tags removed."
    self.probability = 0.0
    _seq_lock.acquire()
    try:
      return self._feedback(user,txt,dspam.DSR_ISINNOCENT)
    finally:
      _seq_lock.release()
