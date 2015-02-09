import unittest
import os
import shutil
from dspam import *

from contextlib import contextmanager

count = 20
hams = ('samp1','amazon','test8')
spams = ('honey','spam44','spam7','spam8','bounce')
home = os.getcwd()+'/testdir'
user = 'testuser'
group = None

@contextmanager
def dspam(mode,flags=0):
  ds = ctx(user,mode,flags,group,home)
  ds.algorithms = DSA_GRAHAM | DSA_BURTON | DSP_GRAHAM
  ds.attach()
  yield ds
  ds.destroy()

class DSpamTestCase(unittest.TestCase):

  def setUp(self):
    try:
      shutil.rmtree(home+'/data')
      os.makedirs(home+'/data/'+user[0]+'/'+user[1]+'/'+user)
    except: pass

  def tearDown(self):
    pass

  def testCorpus(self):
    with dspam(DSM_PROCESS) as ds:
      ds.source = DSS_CORPUS
      ds.classification = DSR_ISINNOCENT
      for ham in hams:
	msg = open('test/'+ham).read()
	msg = '\n'.join(msg.splitlines()).replace('\0','')
	#print 'process corpus',ham
	ds.process(msg)
      self.assertEqual(ds.totals,(0,len(hams),0,0,0,len(hams),0,0))
    with dspam(DSM_PROCESS) as ds:
      ds.source = DSS_CORPUS
      ds.classification = DSR_ISSPAM
      for spam in spams:
	msg = open('test/'+spam).read()
	msg = '\n'.join(msg.splitlines())
	ds.process(msg)
      self.assertEqual(ds.totals,
	  (len(spams),len(hams),0,0,len(spams),len(hams),0,0))

  def testClassify(self):
    with dspam(DSM_CLASSIFY,DSF_SIGNATURE) as ds:
      msg = open('test/'+hams[0]).read()
      msg = '\n'.join(msg.splitlines()).replace('\0','')
      ds.process(msg)
      totals = ds.totals
      sig = ds.signature
      ds.process(msg)
      # check that CLASSIFY changes neither in memory nor on disk totals
      self.assertEqual(ds.totals,totals)
      self.assertEqual(totals,(0,0,0,0,0,0,0,0))
    # test adding the signature later
    with dspam(DSM_PROCESS,DSF_SIGNATURE) as ds:
      ds.source = DSS_ERROR
      ds.classification = DSR_ISSPAM
      ds.process(None,sig=sig)
      self.assertEqual(ds.totals,(1,0,1,0,0,0,0,0))

  # test mime parameter parsing
  def testProcess(self):
    hlen = len(hams)
    slen = len(spams)
    tlen = hlen + slen
    with dspam(DSM_PROCESS,DSF_SIGNATURE) as ds:
      ds.training_mode = DST_TEFT
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
      self.assertEqual(ds.totals,(0,hlen*count,0,0,0,0,0,0))

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

      # now tell it about all that spam
      self.assertEqual(ds.totals,(0,tlen*count,0,0,0,0,0,0))

    with dspam(DSM_PROCESS,DSF_SIGNATURE) as ds:
      ds.classification = DSR_ISSPAM
      ds.source = DSS_ERROR
      ds.training_mode = DST_TEFT
      for spamsig in sigs:
	ds.process(None,sig=spamsig)
      self.assertEqual(ds.totals,(slen*count,hlen*count,slen*count,0,0,0,0,0))

    # exactly the same spam should get rejected with prob = 1.0
    with dspam(DSM_PROCESS,DSF_SIGNATURE) as ds:
      msg = msglist[0]
      ds.process(msg)
      self.assertEqual(ds.result,DSR_ISSPAM)
      self.assertEqual(ds.probability,1.0)
      self.assertEqual(ds.totals,(slen*count+1,hlen*count,slen*count,0,0,0,0,0))
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
    with dspam(DSM_CLASSIFY,DSF_SIGNATURE) as ds:
      ds.process(msg)
      open('msg.out','w').write(msg)
      self.assertEqual(ds.result,DSR_ISSPAM)
      #FIXME: self.failUnless(ds.probability < 1.0)
      self.assertEqual(ds.totals,totals)
      sig = ds.signature

    # actually process with CORPUS
    with dspam(DSM_PROCESS,DSF_SIGNATURE) as ds:
      ds.classification = DSR_ISSPAM
      ds.source = DSS_CORPUS
      ds.process(None,sig=sig)
      self.assertEqual(ds.totals,
      	(slen*count + 2,hlen*count,slen*count,0,1,0,0,0))

      ds.classification = DSR_ISINNOCENT
      ds.source = DSS_ERROR
      ds.process(None,sig=spamsig)
      self.assertEqual(ds.totals,
        (slen*count + 1,hlen*count+1,slen*count,1,1,0,0,0))

    # test false positive via full text
    with dspam(DSM_PROCESS) as ds:
      ds.classification = DSR_ISINNOCENT
      ds.source = DSS_ERROR
      ds.process(msglist[0])
      self.assertEqual(ds.totals,
        (slen*count ,hlen*count+2,slen*count,2,1,0,0,0))

def suite(): return unittest.makeSuite(DSpamTestCase,'test')

if __name__ == '__main__':
  libdspam_init('/usr/lib64/dspam/libhash_drv.so')
  try:
    unittest.main()
  finally:
    libdspam_shutdown()
