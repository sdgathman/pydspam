import unittest
import os
from dspam import *

count = 20
hams = ('samp1','amazon','test8')
spams = ('honey','spam44','spam7','spam8')

class DSpamTestCase(unittest.TestCase):

  def testCorpus(self):
    fname = 'test.dict'
    os.unlink(fname)
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_CORPUS)
    for ham in hams:
      msg = open('test/'+ham).read()
      msg = '\n'.join(msg.splitlines())
      ds.process(msg)
    print ds.totals
    self.assertEqual(ds.totals,(0,len(hams),0,0))
    ds = dspam(fname,DSM_ADDSPAM,DSF_CHAINED|DSF_CORPUS)
    for spam in spams:
      msg = open('test/'+spam).read()
      msg = '\n'.join(msg.splitlines())
      ds.process(msg)
    print ds.totals
    self.assertEqual(ds.totals,(len(spams),len(hams),0,0))

  # test mime parameter parsing
  def testProcess(self):
    fname = 'test.dict'
    os.unlink(fname)
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_SIGNATURE|DSF_NOLOCK)
    ds.lock()
    try:
      # add lots of ham
      msglist = []
      for ham in hams:
	msg = open('test/'+ham).read()
	msg = '\n'.join(msg.splitlines())
	msglist.append(msg)
      for seq in xrange(count):
	for msg in msglist:
	  ds.process(msg)
	  self.assertEqual(ds.result,DSR_ISINNOCENT)
      self.assertEqual(ds.totals,(0,len(hams)*count,0,0))

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
    self.assertEqual(ds.totals,(0,7*count,0,0))
    ds = dspam(fname,DSM_ADDSPAM,DSF_CHAINED|DSF_SIGNATURE|DSF_NOLOCK)
    ds.lock()
    try:
      for spamsig in sigs:
	ds.process(spamsig)
    finally:
      ds.unlock()
    self.assertEqual(ds.totals,(4*count,3*count,4*count,0))

    # exactly the same spam should get rejected with prob = 1.0
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_SIGNATURE)
    msg = msglist[0]
    ds.process(msg)
    self.assertEqual(ds.result,DSR_ISSPAM)
    self.assertEqual(ds.probability,1.0)
    self.assertEqual(ds.totals,(4*count + 1,3*count,4*count,0))

    # a slightly different version of a spam should still get rejected
    lines = msg.splitlines()
    lines[0] = "From: lover <f234235@spam.com>"
    lines[1] = "To: victim <victim@lamb.com>"
    lines[2] = "Subject: Approval"
    msg = '\n'.join(lines)
    ds.process(msg)
    self.assertEqual(ds.result,DSR_ISSPAM)
    self.failUnless(ds.probability < 1.0)
    self.assertEqual(ds.totals,(4*count + 2,3*count,4*count,0))

def suite(): return unittest.makeSuite(DSpamTestCase,'test')

if __name__ == '__main__':
  unittest.main()
