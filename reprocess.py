#!/usr/bin/env python3
# $Log$
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
  print(*msg)

for fname in sys.argv[1:]:
  if not os.path.isfile(fname): continue
  dirname,basename = os.path.split(fname)
  user,ext = basename.split('.')
  lockname = os.path.join(dirname,user + '.retry')
  if ext in ('spam','fp'):
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
          if ext == 'spam':
            log('SPAM:',user)
            ds.add_spam(user,txt)
          else:
            log('FP:',user)
            ds.false_positive(user,txt)
        except Exception as x:
          log('FAIL:',x)
          f = open(os.path.join(dirname,user + '.fail'),'a')
          if not txt.startswith('From '):
            txt = 'From %s %s\n' % (user,time.ctime()) + txt
          f.write(txt)
          f.close()
      fp.close()
      os.unlink(lockname)
    except OSError:
      print('Busy, try later')
