import unittest
import os
import os.path
import Dspam
import dspam
import bsddb
import mailbox
from email.Parser import Parser

userdir = 'testdir'	# test user directory

SPAMS = ('spam1','spam7','spam8','spam44','virus','spam9', 'funky')
HAMS = ('samp1','test8')

class pyDSpamTestCase(unittest.TestCase):

  def setUp(self):
    try: os.makedirs(userdir)
    except OSError: pass
    for f in os.listdir(userdir):
      os.unlink(os.path.join(userdir,f))
    ds = Dspam.DSpamDirectory(userdir)
    fp = open(ds.groupfile,'w')
    fp.write('\n'.join([ "bms:stuart,ed,alb,dmm", "unilit:sil,larry" ])+'\n')
    fp.close()
    # innoculations
    fp = open(os.path.join(userdir,'innoculation'),'w')
    fp.write('\n'.join([ "larry:tonto,stuart", "stuart:sil,tonto" ])+'\n')
    fp.close()
    self.ds = ds
  
  def testGroups(self):
    ds = self.ds
    d = Dspam.parse_groups(ds.groupfile)
    self.failUnless(ds.get_group('stuart') == 'bms')
    self.failUnless(ds.get_group('sil') == 'unilit')
    self.failUnless(ds.get_group('tonto') == 'tonto')
    files = ds.user_files('alb')
    self.failUnless(files == (
      os.path.join(userdir,'bms.dict'),
      os.path.join(userdir,'alb.sig'),
      os.path.join(userdir,'alb.mbox')
    ))

  # Check fallback for lock-timeout during addspam or falsepositive
  def notestLock(self,spams=SPAMS,hams=HAMS):
    ds = self.ds
    overflow = os.path.join(userdir,'tonto.spam')
    self.failIf(os.path.exists(overflow))
    txt = open('test/samp1').read()	# innocent mail
    ds.check_spam('tonto',txt)
    txt = open('test/spam7').read()	# spam mail
    txt = ds.check_spam('tonto',txt)
    # OK, now lock the dict with another context
    ds1 = dspam.dspam(ds.dspam_dict,dspam.DSM_PROCESS,0)
    ds1.lock()
    # and try to process addspam while locked
    ds.add_spam('tonto',txt)
    try:
      ds.check_spam('tonto',txt)
    except dspam.error,x:
      if not x.strerror: x.strerror = x.args[0]
      self.failUnless(x.strerror == 'Lock failed')
    ds1.unlock()
    # check that message got written to overflow
    self.failUnless(os.path.exists(overflow))

  def testProcess(self):
    ds = self.ds
    msgs = []
    # check that all kinds of messages get properly tagged
    spams = SPAMS
    hams = HAMS
    for fname in spams + hams:
      txt = open(os.path.join('test',fname)).read()
      msgs.append(ds.check_spam('tonto',txt))

    # check that sigs are all present
    db = bsddb.btopen(ds.user_files('tonto')[1],'r')
    for txt in msgs:
      txt,tag = Dspam.extract_signature_tags(txt)
      self.failUnless(len(tag) == 1)
      self.failUnless(db.has_key(tag[0]))
    db.close()

    for txt in spams:
      txt = open(os.path.join('test',fname)).read()
      ds.add_spam('tonto',txt)		# feedback spam
      tot = ds.totals
    self.assertEqual(tot,(len(spams),len(msgs),len(spams),0))

    # check that sigs were deleted
    dspam_dict,sigfile,mbox = ds.user_files('tonto')
    db = bsddb.btopen(sigfile,'r')
    for txt in spams:
      txt = open(os.path.join('test',fname)).read()
      tag = Dspam.extract_signature_tags(txt)
      self.failIf(db.has_key(tag[0]))
    db.close()
    
    # receive and feedback spams until one gets quarantined
    while True:
      txt = open('test/spam7').read()	# spam mail
      txt = ds.check_spam('tonto',txt)
      if not txt: break	# message was quarantined
      ds.add_spam('tonto',txt)
      tot = ds.totals
      txt = open('test/samp1').read()	# innocent mail
      txt = ds.check_spam('tonto',txt)
      self.failUnless(txt)

    # now receive a message that will be a false positive
    # I manually ran dspam_anal.py to find spammy keywords after
    # the above, then constructed a message that is detected as spam.

    txt = open('test/fp1').read()	# innocent mail that looks spammy
    txt = ds.check_spam('tonto',txt)
    self.failIf(txt)	# message should have been quarrantined
    fp = open(mbox)
    parser = Parser()
    mb = mailbox.PortableUnixMailbox(fp,parser.parse)
    msg = mb.next()	# first message is spam
    self.assertEqual(msg.get('subject'),
	'Just another "Crappy Day in Paradise" here @ the Ranch')
    msg = mb.next()	# get 2nd message, which should be our false positive
    self.assertEqual(msg.get('subject'),'one more unit test')
    txt = msg.as_string()
    ds.false_positive('tonto',txt)	# feedback as false positive
    tot = ds.totals
    self.assertEqual(tot[3],1)	# should be 1 FP

    # now receive the innocent mail again, it should not look spammy anymore.
    txt = open('test/fp1').read()	# now innocent looking mail
    txt = ds.check_spam('tonto',txt)
    # haven't got stats right
    #self.failUnless(txt)

def suite(): return unittest.makeSuite(pyDSpamTestCase,'test')

if __name__ == '__main__':
  import sys
  if len(sys.argv) > 1:
    ds = Dspam.DSpamDirectory(userdir)
    for fname in sys.argv[1:]:
      txt = open(fname).read()
      print ds.check_spam('tonto',txt)
  else:
    unittest.main()
