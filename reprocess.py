#!/usr/bin/env python2
# $Log$
import mailbox
import sys
import os
import os.path
import mime
import time
import Dspam

def log(*msg):
  for i in msg: print i,
  print

for fname in sys.argv[1:]:
  if not os.path.isfile(fname): continue
  dirname,basename = os.path.split(fname)
  user,ext = basename.split('.')
  lockname = os.path.join(dirname,user + '.retry')
  if ext == 'spam':
    try:
      os.link(fname,lockname)
      os.unlink(fname)
      ds = Dspam.DSpamDirectory(dirname)
      ds.log = log
      fp = open(lockname,'r')
      mbox = mailbox.PortableUnixMailbox(fp,mime.MimeMessage)
      for msg in mbox:
	log('Subject:',msg['subject'])
	txt = msg.as_string()
	try:
	  ds.add_spam(user,txt)
	except Exception,x:
	  log('FAIL:',x)
	  f = open(os.path.join(dirname,user + '.fail'),'a')
	  if not txt.startswith('From '):
	    txt = 'From %s %s\n' % (user,time.ctime()) + txt
	  f.write(txt)
	  f.close()
      fp.close()
      os.unlink(lockname)
    except OSError:
      print 'Busy, try later'
