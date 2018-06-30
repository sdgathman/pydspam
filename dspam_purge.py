#!/usr/bin/python2

import sys
import bsddb
import dspam
import struct
import time
import os

PURGE_BELOW_QUOTA   =    86400 * 45
PURGE_NO_SPAM_HITS  =    86400 * 30
PURGE_ONE_INNOCENT_HIT = 86400 * 15
DEBUG = False

def rename(src,dst):
  try: os.rename(src,dst)
  except OSError:
    os.remove(dst)
    os.rename(src,dst)

userdir = '/var/lib/dspam'

if len(sys.argv) < 2:
  print >>sys.stderr,'syntax: dspam_dump [user] ...'
  sys.exit(2)

for user in sys.argv[1:]:
  if os.path.isabs(user):
    dict = user
  else:
    dict = os.path.join(userdir,'%s.dict'%user)
  #dict = 'test.dict'
  ds = dspam.dspam(dict,dspam.DSM_PROCESS,dspam.DSF_NOLOCK)

  ds.lock()

  start_time = time.time()
  try:
    db = bsddb.btopen(dict,'r')
    newdict = bsddb.btopen(dict+'.new','n')
    try:
      deleted = 0
      key,data = db.first()
      totalrec = None
      while 1:
	if key == '_TOTALS':
	  # If we've already seen totals, then db is looped
	  if totalrec: break	
	  totalrec = struct.unpack('llll',data)
	  print 'TOTALS: TS: %d TI: %d TM: %d FP: %d' % totalrec
	  newdict[key] = data
	else:
	  spam_hits,innocent_hits,last_hit = struct.unpack('lll',data)
	  if spam_hits + innocent_hits * 2 < 5:
	    delta = start_time - last_hit
	    if delta > PURGE_BELOW_QUOTA or (
	      spam_hits == 0 and (
	        delta > PURGE_NO_SPAM_HITS or
		innocent_hits == 1 and delta > PURGE_ONE_INNOCENT_HIT)):
	      ++deleted
	      if DEBUG:
		crc = struct.unpack('Q',key)[0]
		print 'DELETING: %16x: %d %d' % (crc,spam_hits,innocent_hits)
	    else:
	      newdict[key] = data
	  else:
	    newdict[key] = data

	key,data = db.next()
    except KeyError: pass
    db.close()
    newdict.close()
    # FIXME: set permissions on new dict
    rename(dict,dict+'.old')
    rename(dict+'.new',dict)
  finally:
    ds.unlock()
    ds.destroy()
