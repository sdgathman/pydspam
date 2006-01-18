#!/usr/bin/env python2.4
import sys
import bsddb
import dspam
import struct
import time
import os
import mime

userdir = '/var/lib/dspam'
maxtokens = 15

# FIXME: duplicates logic in libdspam.c: _ds_load_stat()
def load_stat(db,crc,totals):
  key = struct.pack('Q',crc);
  try:  spam_hits,innocent_hits,last_hit = struct.unpack('lll',db[key])
  except KeyError: return (.4,0,0)
  total_spam,total_innocent,sm,fp = totals
  if spam_hits > total_spam: spam_hits = total_spam
  if innocent_hits > total_innocent: innocent_hits = total_innocent
  sp = spam_hits * 1.0 / total_spam
  ip = innocent_hits * 1.0 / total_innocent
  probability = sp / (sp + ip)
  min_hits = 5
  if total_innocent < 500:
    min_hits = 20

  if total_innocent < 1000 and total_innocent >= 500:
    spams = total_spam*100.0/(total_spam+total_innocent)
    if spams > 20:
      min_hits = 5+(spams/2)

  if innocent_hits < 0: innocent_hits = 0
  if spam_hits < 0: spam_hits = 0

  if spam_hits == 0 and innocent_hits > 0:
    if innocent_hits > 50: probability = 0.0060
    elif innocent_hits > 10: probability = 0.0099
    else: probability = 0.0100
  elif spam_hits > 0 and innocent_hits == 0:
    if spam_hits >= 10: probability = 0.9901
    else: probability = 0.9900

  if spam_hits + (2*innocent_hits)<min_hits or total_innocent < min_hits:
      probability = .4

  if probability < 0.0010:
    probability = 0.0010

  if probability > 0.9990:
    probability = 0.9990
  return probability,spam_hits,innocent_hits

def analyzeMessage(ds,fp,headeronly=0,maxstat=15):
  msg = mime.MimeMessage(fp)
  for part in msg.walk():
    if part.get_content_maintype() == 'text':
      txt = part.get_payload(decode=True)
      #del msg["content-transfer-encoding"]
      msg.set_payload(txt)
  fp.close()
  msg = msg.as_string()
  if headeronly:
    hdr,body = msg.split('\n\n',1)
    del msg
    body = ' '
    ds.process(hdr + '\n\n')
  else:
    ds.process(msg)
    hdr,body = msg.split('\n\n',1)
    del msg
  sig = ds.signature
  totals = ds.totals
  totprob = ds.probability
  bay_top = 0.0 # AB
  bay_bot = 0.0 # (1-A)(1-B)
  print "TS: %d TI: %d TM: %d FP: %d" % totals
  print "DSPAM spam probability = %f" % totprob
  tok = dspam.tokenize(hdr,body)
  sig = struct.unpack('Q'*(len(sig)/8),sig)
  db = bsddb.btopen(dict,'r')
  try:
    print "%8s %8s %8s %4s %s" % (
      "spamhits","innocent","prob","freq","token")
    for crc in sig:
      prob,spam_hits,innocent_hits = load_stat(db,crc,totals)
      try: token,freq = tok[crc]
      except KeyError: token,freq = '???',-1

      if maxstat > 0:
        maxstat -= 1
	if bay_top == 0.0: bay_top = prob
	else: bay_top *= prob
	if bay_bot == 0.0: bay_bot = 1-prob
	else: bay_bot *= (1-prob)
        print "%8d %8d %8f %4d %8f %s" % (
	  spam_hits,innocent_hits,prob,freq,bay_top / (bay_bot + bay_top),token)
      else:
        print "%8d %8d %8f %4d %s" % (
	  spam_hits,innocent_hits,prob,freq,token)

    probability = bay_top / (bay_top + bay_bot);
    print "Calculated probability = %f" % probability
  finally:
    db.close()

if len(sys.argv) < 2:
  print >>sys.stderr,'syntax: dspam_anal user|dict [-h] [message ...]'
  sys.exit(2)

user = sys.argv[1]
if os.path.isabs(user) or user.endswith('.dict'):
  dict = user
else:
  dict = os.path.join(userdir,'%s.dict'%user)
#dict = 'test.dict'
ds = dspam.dspam(dict,dspam.DSM_PROCESS,
  dspam.DSF_NOLOCK|dspam.DSF_CLASSIFY|dspam.DSF_CHAINED|dspam.DSF_SIGNATURE)

ds.lock()
try:
  if len(sys.argv) == 2:
    analyzeMessage(ds,sys.stdin)
  else:
    headeronly = 0
    for fname in sys.argv[2:]:
      if fname == '-h': headeronly = 1
      else: analyzeMessage(ds,open(fname,'r'),headeronly)
finally:
  ds.unlock()
  ds.destroy()
