import unittest
import os
from dspam import *

count = 20
hams = ('samp1','amazon','test8')
spams = ('honey','spam44','spam7','spam8','bounce')
fname = 'test.dict'

class DSpamTestCase(unittest.TestCase):

  def testCorpus(self):
    try: os.unlink(fname)
    except: pass
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_CORPUS)
    for ham in hams:
      msg = open('test/'+ham).read()
      msg = '\n'.join(msg.splitlines()).replace('\0','')
      ds.process(msg)
    self.assertEqual(ds.totals,(0,len(hams),0,0))
    ds.destroy()
    ds = dspam(fname,DSM_ADDSPAM,DSF_CHAINED|DSF_CORPUS)
    for spam in spams:
      msg = open('test/'+spam).read()
      msg = '\n'.join(msg.splitlines())
      ds.process(msg)
    self.assertEqual(ds.totals,(len(spams),len(hams),len(spams),0))
    ds.destroy()

  def testClassify(self):
    try: os.unlink(fname)
    except: pass
    ds = dspam(fname,DSM_PROCESS,DSF_CLASSIFY|DSF_CHAINED|DSF_SIGNATURE)
    msg = open('test/'+hams[0]).read()
    msg = '\n'.join(msg.splitlines()).replace('\0','')
    ds.process(msg)
    totals = ds.totals
    sig = ds.signature
    ds.process(msg)
    # check that CLASSIFY changes neither in memory nor on disk totals
    self.assertEqual(ds.totals,totals)
    self.assertEqual(totals,(0,0,0,0))
    ds.destroy()
    # test adding the signature later
    ds = dspam(fname,DSM_ADDSPAM,DSF_CORPUS|DSF_CHAINED|DSF_SIGNATURE)
    ds.process(sig)
    self.assertEqual(ds.totals,(1,0,0,0))
    ds.destroy()

  # test base64 decoding in libdspam
  def oldtestCopyback(self):
    try: os.unlink(fname)
    except: pass
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_COPYBACK)
    msg = open('test/bounce').read()
    ds.process('\n'.join(msg.splitlines()))
    copyback = ds.copyback
    self.failUnless(len(copyback) > 0 and len(copyback) < len(msg))
    # test no base64 segment
    msg = open('test/amazon').read()
    # copyback adds an extra newline - no big deal
    ds.process('\n'.join(msg.splitlines()))
    copyback = ds.copyback
    self.failUnless(copyback == msg)
    ds.destroy()
    
  # test mime parameter parsing
  def testProcess(self):
    hlen = len(hams)
    slen = len(spams)
    tlen = hlen + slen
    try: os.unlink(fname)
    except: pass
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_SIGNATURE|DSF_NOLOCK)
    ds.lock()
    try:
      # add lots of ham
      msglist = []
      for ham in hams:
	msg = open('test/'+ham).read()
	msg = '\n'.join(msg.splitlines()).replace('\0','')
	msglist.append(msg)
      for seq in xrange(count):
	for msg in msglist:
	  ds.process(msg)
	  self.assertEqual(ds.result,DSR_ISINNOCENT)
      self.assertEqual(ds.totals,(0,hlen*count,0,0))

      # add lots of spam and save the sigs
      sigs = []
      msglist = []
      for spam in spams:
	msg = open('test/'+spam).read()
	msg = '\n'.join(msg.splitlines())
	msglist.append(msg)
      for seq in xrange(count):
	for msg in msglist:
	  ds.process(msg)
	  # don't know its spam yet
	  self.assertEqual(ds.result,DSR_ISINNOCENT)
	  sigs.append(ds.signature)
    finally:
      ds.unlock()

    # now tell it about all that spam
    self.assertEqual(ds.totals,(0,tlen*count,0,0))
    ds = dspam(fname,DSM_ADDSPAM,DSF_CHAINED|DSF_SIGNATURE|DSF_NOLOCK)
    ds.lock()
    try:
      for spamsig in sigs:
	ds.process(spamsig)
    finally:
      ds.unlock()
    self.assertEqual(ds.totals,(slen*count,hlen*count,slen*count,0))

    # exactly the same spam should get rejected with prob = 1.0
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_SIGNATURE)
    msg = msglist[0]
    ds.process(msg)
    self.assertEqual(ds.result,DSR_ISSPAM)
    self.assertEqual(ds.probability,1.0)
    self.assertEqual(ds.totals,(slen*count + 1,hlen*count,slen*count,0))
    totals = ds.totals
    spamsig = ds.signature # save for FALSEPOSITIVE test

    # a slightly different version of a spam should still get rejected
    lines = msg.splitlines()
    lines[0] = "From: lover <f234235@spam.com>"
    #lines[1] = "To: victim <victim@lamb.com>"
    lines[2] = "Subject: Approval"
    lines = filter(lambda ln: ln.find("Q2Xet") < 0,lines)
    msg = '\n'.join(lines)

    # test DSF_CLASSIFY
    ds = dspam(fname,DSM_PROCESS,DSF_CLASSIFY|DSF_CHAINED|DSF_SIGNATURE)
    ds.process(msg)
    open('msg.out','w').write(msg)
    self.assertEqual(ds.result,DSR_ISSPAM)
    self.failUnless(ds.probability < 1.0)
    self.assertEqual(ds.totals,totals)
    sig = ds.signature

    # actually process with CORPUS
    ds = dspam(fname,DSM_ADDSPAM,DSF_CORPUS|DSF_CHAINED|DSF_SIGNATURE)
    ds.process(sig)
    self.assertEqual(ds.totals,(slen*count + 2,hlen*count,slen*count,0))

    # test false positive via signature
    ds = dspam(fname,DSM_FALSEPOSITIVE,DSF_CHAINED|DSF_SIGNATURE)
    ds.process(spamsig)
    self.assertEqual(ds.totals,(slen*count + 1,hlen*count+1,slen*count,1))

    # test false positive via full text
    ds = dspam(fname,DSM_FALSEPOSITIVE,DSF_CHAINED)
    ds.process(msglist[0])
    self.assertEqual(ds.totals,(slen*count ,hlen*count+2,slen*count,2))

def suite(): return unittest.makeSuite(DSpamTestCase,'test')

if __name__ == '__main__':
  unittest.main()
