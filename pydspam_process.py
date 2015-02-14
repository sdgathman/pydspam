#!/usr/bin/env python2.6
# $Log$
# Revision 2.1  2015/02/11 22:06:04  customdesigned
# Merge pydspam-3-branch to trunk
#
# Revision 1.1.2.3  2011/08/03 21:18:06  customdesigned
# python2.6
#
# Revision 1.1.2.2  2005/06/04 17:39:10  stuart
# Release 1.1.8 for python2.4
#
# Revision 1.1.2.1  2004/03/29 22:47:17  stuart
# Release 1.1.6
#
# Revision 2.6.4.1  2004/01/14 21:09:32  stuart
# Postphone reprocessing if lock file is busy.
#
# Revision 2.6  2003/11/03 21:12:13  stuart
# Test null bytes in messages.
# Test "Lock failed" exception
#
# Revision 2.5  2003/10/22 21:47:32  stuart
# Reprocess false positives also.
#
# Revision 2.4  2003/10/22 02:03:17  stuart
# Add From header for reprocessing failures
#
import mailbox
import sys
import os
import os.path
import mime
import time
import Dspam

def log(*msg):
  print time.strftime('%Y%b%d %H:%M:%S'),
  for i in msg: print i,
  print

def process_queue(fname):
  if not os.path.isfile(fname): return False
  dirname,basename = os.path.split(fname)
  user,ext = basename.split('.')
  if ext not in ('spam','fp'): return False
  lockname = os.path.join(dirname,user + '.retry')
  dlockname = os.path.join(dirname,user + '.lock')
  if os.path.exists(dlockname):
    log('Busy, finish later.')
    return True
  try:
    os.link(fname,lockname)
    os.unlink(fname)
    ds = Dspam.DSpamDirectory(dirname)
    ds.log = log
    with open(lockname,'r') as fp:
      mbox = mailbox.PortableUnixMailbox(fp,mime.MimeMessage)
      for msg in mbox:
	log('Subject:',msg['subject'])
	txt = msg.as_string()
	try:
	  if ext == 'spam':
	    log('SPAM:',user)
	    ds.add_spam(user,txt)
	  else:
	    log('FP:',user)
	    ds.false_positive(user,txt)
	except Exception,x:
	  log('FAIL:',x)
	  with open(os.path.join(dirname,user + '.fail'),'a') as f:
	    if not txt.startswith('From '):
	      txt = 'From %s %s\n' % (user,time.ctime()) + txt
	    f.write(txt)
    os.unlink(lockname)
    return False
  except OSError:
    print 'Busy, try later'
    return True

for fname in sys.argv[1:]:
  if process_queue(fname): break
