#!/usr/bin/env python2

import sys
import bsddb
import dspam
import struct
import time
import os

userdir = '/var/lib/dspam'

if len(sys.argv) < 2:
  print >>sys.stderr,'syntax: dspam_dump [user] ...'
  sys.exit(2)

for user in sys.argv[1:]:
  if os.path.isabs(user) or user.endswith('.dict'):
    dict = user
  else:
    dict = os.path.join(userdir,'%s.dict'%user)
  #dict = 'test.dict'
  ds = dspam.dspam(dict,dspam.DSM_PROCESS,dspam.DSF_NOLOCK)

  ds.lock()

  try:
    db = bsddb.btopen(dict,'r')
    try:
      key,data = db.first()
      while 1:
	if key == '_TOTALS':
	  rec = struct.unpack('llll',data)
	  print 'TOTALS: TS: %d TI: %d TM: %d FP: %d' % rec
	else:
	  rec = struct.unpack('lll',data)
	  crc = struct.unpack('Q',key)[0]
	  print '%16x S: %8d I: %8d LH: %s' % (
	    crc,rec[0],rec[1],time.ctime(rec[2])
	  )
	key,data = db.next()
    except KeyError: pass
    db.close()
  finally: ds.unlock()
