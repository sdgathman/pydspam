#!/usr/bin/env python2
# command line utility to add 

import sys
import mailbox
from dspam import *

def usage():
  print >>sys.stderr, "Usage:	%s user filename [--addspam]" % sys.argv[0]
  sys.exit(2)

def msgAsString(msg):
  lines = [msg.unixfrom]
  lines.extend(msg.headers)
  lines.append('\n')
  msg.rewindbody()
  lines.append(msg.fp.read())
  return ''.join(lines)

if len(sys.argv) < 3: usage()
user = sys.argv[1]
file = sys.argv[2]

mode = DSM_PROCESS
for opt in sys.argv[3:]:
  if opt == '-a' or opt == '--addspam':
    mode = DSM_ADDSPAM
  else:
    usage()

if user.find('/') >= 0:
  dict = "%s.dict" % user
else:
  dict = "/var/lib/dspam/%s.dict" % user

f = open(file,"r")
mbox = mailbox.PortableUnixMailbox(f)
ds = dspam(dict,mode,DSF_CORPUS|DSF_CHAINED|DSF_NOLOCK)
ds.lock()
try:
  for msg in iter(mbox.next,None):
    print msg.unixfrom.strip()
    data = msgAsString(msg)
    ds.process(data)
  totals = ds.totals
finally:
  ds.unlock()
print "TS=%d TI=%d TM=%d FP=%d" % totals
