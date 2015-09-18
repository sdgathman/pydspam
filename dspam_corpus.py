#!/usr/bin/env python2.6
# command line utility to add spams
# Obsolete: dspam-3.10 has command line utilities

import sys
import mailbox
import time
import bsddb
import struct
from dspam import *

start_time = time.time()

def usage():
  print >>sys.stderr, "Usage:	%s user filename [--addspam]" % sys.argv[0]
  print >>sys.stderr, "NOTE: this is obsolete, you probably want dspam_train"
  sys.exit(2)

def msgAsString(msg):
  lines = [msg.unixfrom]
  lines.extend(msg.headers)
  lines.append('\n')
  msg.rewindbody()
  lines.append(msg.fp.read())
  return ''.join(lines)

def addCorpus(db,buf,mode):
  hdr,body = buf.split('\n\n',1)
  try: ts,ti,tm,fp = struct.unpack('llll',db['_TOTALS'])
  except KeyError: ts,ti,tm,fp = 0,0,0,0
  for crc in tokenize(hdr,body).keys():
    key = struct.pack('Q',crc)
    try:
      spam_hits,innocent_hits,last_hit = struct.unpack('lll',db[key])
    except KeyError:
      spam_hits,innocent_hits = 0,0
    if mode == DSM_ADDSPAM: spam_hits += 1
    else: innocent_hits += 1
    db[key] = struct.pack('lll',spam_hits,innocent_hits,start_time)
  if mode == DSM_ADDSPAM: ts += 1
  else: ti += 1
  db['_TOTALS'] = struct.pack('llll',ts,ti,tm,fp)
  return (ts,ti,tm,fp)

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
file_lock(dict)
db = bsddb.btopen(dict,'c')
try:
  for msg in iter(mbox.next,None):
    print msg.unixfrom.strip()
    data = msgAsString(msg)
    totals = addCorpus(db,data,mode)
finally:
  db.close()
  file_unlock(dict)
print "TS=%d TI=%d TM=%d FP=%d" % totals
