import unittest
import os
from dspam import *

count = 20

class DSpamTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testProcess(self):
    fname = 'test.dict'
    os.unlink(fname)
    ds = dspam(fname,DSM_PROCESS,DSF_CHAINED|DSF_SIGNATURE|DSF_NOLOCK)
    try:
      ds.lock()
      try:
        for seq in xrange(count):
	  for ham in ('samp1','amazon','test8'):
	    msg = open('test/'+ham).read()
	    ds.process(msg)
	self.assertEqual(ds.totals,(0,3*count,0,0))

	sigs = []
	for seq in xrange(count):
	  for spam in ('honey','spam44','spam7','spam8'):
	    msg = open('test/'+spam).read()
	    ds.process(msg)
	    sigs.append(ds.signature)
      finally:
        ds.unlock()
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
      msg = open('test/honey').read()
      ds.process(msg)
      self.assertEqual(ds.probability,1.0)
      self.assertEqual(ds.totals,(4*count + 1,3*count,4*count,0))
      # a slightly different version of a spam should still get rejected
      lines = msg.splitlines()
      lines[0] = "From: lover <f234235@spam.com>"
      lines[1] = "To: victim <victim@lamb.com>"
      lines[2] = "Subject: Approval"
      msg = '\n'.join(lines)
      ds.process(msg)
      self.failUnless(ds.probability < 1.0)
      self.assertEqual(ds.totals,(4*count + 2,3*count,4*count,0))
    finally:
      del ds

def suite(): return unittest.makeSuite(DSpamTestCase,'test')

if __name__ == '__main__':
  unittest.main()
