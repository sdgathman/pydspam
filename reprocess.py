import mailbox
import sys
import os
import os.path
import mime
import Dspam

for fname in sys.argv[1:]:
  dirname,basename = os.path.split(fname)
  user,ext = basename.split('.')
  lockname = os.path.join(dirname,user + '.retry')
  if ext == 'spam':
    try:
      os.link(fname,lockname)
      os.unlink(fname)
      ds = Dspam.DSpamDirectory(dirname)
      fp = open(lockname,'r')
      mbox = mailbox.PortableUnixMailbox(fp,mime.MimeMessage)
      for msg in mbox:
	print 'Subject: %s' % msg['subject']
	txt = msg.as_string()
	ds.add_spam(user,txt)
      fp.close()
      os.unlink(lockname)
    except OSError:
      print 'Busy, try later'
