import unittest
import os
from dspam import *

count = 20
hams = ('samp1','amazon','test8')
spams = ('honey','spam44','spam7','spam8','bounce')
home = os.getcwd()+'/testdir'
user = 'testuser'
group = 'testgroup'

class DSpamTestCase(unittest.TestCase):

  def setUp(self):
    try: os.makedirs(home)
    except: pass

  def tearDown(self):
    pass

  def testCorpus(self):
    ds = dspam(user,DSM_PROCESS,0,group,home)
    ds.source = DSS_CORPUS
    ds.classification = DSR_ISINNOCENT
    for ham in hams:
      msg = open('test/'+ham).read()
      msg = '\n'.join(msg.splitlines()).replace('\0','')
      ds.process(msg)
    self.assertEqual(ds.totals,(0,len(hams),0,0))
    ds.destroy()
    ds = dspam(user,DSM_PROCESS,0,group,home)
    ds.source = DSS_CORPUS
    ds.classification = DSR_ISSPAM
    for spam in spams:
      msg = open('test/'+spam).read()
      msg = '\n'.join(msg.splitlines())
      ds.process(msg)
    self.assertEqual(ds.totals,(len(spams),len(hams),len(spams),0))
    ds.destroy()

  def testClassify(self):
    ds = dspam(user,DSM_CLASSIFY,DSF_SIGNATURE,group,home)
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
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
    ds.source = DSS_ERROR
    ds.classification = DSR_ISSPAM
    ds.process(sig)
    self.assertEqual(ds.totals,(1,0,0,0))
    ds.destroy()

  # test mime parameter parsing
  def testProcess(self):
    hlen = len(hams)
    slen = len(spams)
    tlen = hlen + slen
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
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

    # now tell it about all that spam
    self.assertEqual(ds.totals,(0,tlen*count,0,0))
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
    ds.classification = DSR_ISSPAM
    ds.source = DSS_ERROR
    for spamsig in sigs:
      ds.process(spamsig)
    self.assertEqual(ds.totals,(slen*count,hlen*count,slen*count,0))
    ds.destroy()

    # exactly the same spam should get rejected with prob = 1.0
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
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
    ds = dspam(user,DSM_CLASSIFY,DSF_SIGNATURE,group,home)
    ds.process(msg)
    open('msg.out','w').write(msg)
    self.assertEqual(ds.result,DSR_ISSPAM)
    self.failUnless(ds.probability < 1.0)
    self.assertEqual(ds.totals,totals)
    sig = ds.signature

    # actually process with CORPUS
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
    ds.classification = DSR_ISSPAM
    ds.source = DSS_CORPUS
    ds.process(sig)
    self.assertEqual(ds.totals,(slen*count + 2,hlen*count,slen*count,0))

    # test false positive via signature
    ds = dspam(user,DSM_PROCESS,DSF_SIGNATURE,group,home)
    ds.classification = DSR_ISINNOCENT
    ds.source = DSS_ERROR
    ds.process(spamsig)
    self.assertEqual(ds.totals,(slen*count + 1,hlen*count+1,slen*count,1))

    # test false positive via full text
    ds = dspam(user,DSM_FALSEPOSITIVE,0,group,home)
    ds.classification = DSR_ISINNOCENT
    ds.source = DSS_ERROR
    ds.process(msglist[0])
    self.assertEqual(ds.totals,(slen*count ,hlen*count+2,slen*count,2))

def suite(): return unittest.makeSuite(DSpamTestCase,'test')

if __name__ == '__main__':
  print 'begin'
  libdspam_init('/usr/lib64/dspam/libhash_drv.so')
  print 'after init'
  try:
    init_driver(None)
    print 'after init_driver'
    unittest.main()
    shutdown_driver(None)
  finally:
    libdspam_shutdown()
