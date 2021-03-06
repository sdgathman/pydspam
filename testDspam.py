from __future__ import print_function
import unittest
import os
import os.path
import shutil
import Dspam
import dspam
import mailbox
try:
  from email.parser import BytesParser as Parser
except:
  from email.parser import Parser

userdir = 'testdir'	# test user directory

SPAMS = ('spam1','spam7','spam8','spam44','virus', 'funky')
HAMS = ('samp1','test8')

class pyDSpamTestCase(unittest.TestCase):

  def setUp(self):
    try:
      shutil.rmtree(userdir+'/data')
      savmask = os.umask(0o006) # mail group must be able write dict and sig
      try:
        os.makedirs(userdir+'/data')
      finally: os.umask(savmask)
    except OSError: pass
    ds = Dspam.DSpamDirectory(userdir)
    with open(ds.groupfile,'w') as fp:
      fp.write('\n'.join([ "bms:stuart,ed,alb,dmm", "unilit:sil,larry" ])+'\n')
    # innoculations
    with open(os.path.join(userdir,'innoculation'),'w') as fp:
      fp.write('\n'.join([ "larry:tonto,stuart", "stuart:sil,tonto" ])+'\n')
    self.ds = ds
  
  def testGroups(self):
    ds = self.ds
    d = Dspam.parse_groups(ds.groupfile)
    self.assertEqual(ds.get_group('stuart'),'bms')
    self.assertEqual(ds.get_group('sil'),'unilit')
    self.assertEqual(ds.get_group('tonto'),'tonto')
    files = ds.user_files('alb')
    # FIXME: figure how to test for new API
    #self.assertEqual(files,(
    #  os.path.join(userdir,'bms.dict'),
    #  os.path.join(userdir,'alb.sig'),
    #  os.path.join(userdir,'alb.mbox')
    #))

  # Check fallback for lock-timeout during addspam or falsepositive
  def notestLock(self,spams=SPAMS,hams=HAMS):
    ds = self.ds
    overflow = os.path.join(userdir,'tonto.spam')
    self.failIf(os.path.exists(overflow))
    txt = open('test/samp1','rb').read()	# innocent mail
    ds.check_spam('tonto',txt)
    txt = open('test/spam7','rb').read()	# spam mail
    txt = ds.check_spam('tonto',txt)
    # OK, now lock the dict with another context
    ds1 = dspam.dspam(ds.dspam_dict,dspam.DSM_PROCESS,0)
    ds1.lock()
    # and try to process addspam while locked
    ds.add_spam('tonto',txt)
    try:
      ds.check_spam('tonto',txt)
    except dspam.error as x:
      if not x.strerror: x.strerror = x.args[0]
      self.assertEqual(x.strerror,'Lock failed')
    ds1.unlock()
    # check that message got written to overflow
    self.assertTrue(os.path.exists(overflow))
  def log(self,*msg):
    print(*msg)

  def testProcess(self):
    ds = self.ds
    msgs = {}
    # check that all kinds of messages get properly tagged
    spams = SPAMS
    hams = HAMS
    #ds.log = self.log
    for fname in spams + hams:
      with open(os.path.join('test',fname),'rb') as fp:
        msgs[fname] = ds.check_spam('tonto',fp.read())
      self.assertEqual(ds.result,dspam.DSR_ISINNOCENT)
    self.assertEqual(ds.totals,(0,len(msgs),0,0,0,0,0,0))

    # check that sigs are all present
    with ds.dspam_ctx(dspam.DSM_TOOLS) as db:
      for fname,txt in msgs.items():
        ntxt,tag = Dspam.extract_signature_tags(txt)
        if not tag:
          with open('msg.out','wb') as fp: fp.write(txt)
        self.assertEqual(len(tag),1,fname+' missing tag')
        self.assertTrue(db.verify_signature(tag[0]))

    for fname in spams:
      txt = ds.add_spam('tonto',msgs[fname])		# feedback spam
      self.assertTrue(txt is not None)
      ntxt,tag = Dspam.extract_signature_tags(txt)
      self.assertEqual(len(tag),0,fname+' tag not removed')

    self.assertEqual(ds.totals,(len(spams),len(hams),len(spams),0,0,0,0,0))

    # check that sigs were deleted
    dspam_dict,sigfile,mbox = ds.user_files('tonto')
    with ds.dspam_ctx(dspam.DSM_TOOLS) as db:
      for fname in spams:
        txt = msgs[fname]
        ntxt,tags = Dspam.extract_signature_tags(txt)
        self.failIf(db.verify_signature(tags[0]))
    
    # receive and feedback spams until one gets quarantined
    while True:
      with open('test/spam7','rb') as fp:	# spam mail
        txt = ds.check_spam('tonto',fp.read())
      if not txt: break	# message was quarantined
      ds.add_spam('tonto',txt)
      with open('test/samp1','rb') as fp:	# innocent mail
        txt = ds.check_spam('tonto',fp.read())
      self.assertTrue(txt)		# should not have been quarantined

    # now receive a message that will be a false positive
    # I manually ran dspam_anal.py to find spammy keywords after
    # the above, then constructed a message that is detected as spam.

    with open('test/fp1','rb') as fp:	# innocent mail that looks spammy
      txt = ds.check_spam('tonto',fp.read())
    self.failIf(txt)	# message should have been quarrantined
    parser = Parser()
    try:
      m = mailbox.mbox(mbox,parser.parse)
      mb = m.itervalues()
      msg = mb.__next__()	# first message is spam
      self.assertEqual(msg.get('subject'),
          'Just another "Crappy Day in Paradise" here @ the Ranch')
      msg = mb.__next__()	# get 2nd message: should be our false positive
      self.assertEqual(msg.get('subject'),'Just another unit test')
      txt = msg.as_bytes()
    finally: m.close()
    ds.false_positive('tonto',txt)	# feedback as false positive
    tot = ds.totals
    self.assertEqual(tot[3],1)	# should be 1 FP

    # now receive the innocent mail again, it should not look spammy anymore.
    with open('test/fp1','rb') as fp:	# now innocent looking mail
      txt = ds.check_spam('tonto',fp.read())
    # haven't got stats right
    #self.assertTrue(txt)

import mime

class tagTestCase(unittest.TestCase):

  def testtag(self):
    with open('test/spam1','rb') as fp:
      msg = mime.message_from_file(fp)
    self.assertTrue(not msg.get_payload() is None)
    sigkey = 'TESTING123'
    Dspam.add_signature_tag(msg,sigkey,prob=0.99)
    self.assertTrue(msg.ismodified())
    txt,tags = Dspam.extract_signature_tags(msg.as_bytes())
    self.assertEqual(len(tags),1)
    self.assertEqual(sigkey,tags[0])

  # somehow, tags are getting split by =<NL>.  It might be possible
  # that our _tag_part is doing it when recoding, but I can't come up
  # with an example.  So I punted and tested that extraction can correct
  # the problem in most cases by manually adding a split tag to the test msg.
  def testquote(self):
    fp = open('test/spam3','rb')
    msg = mime.message_from_file(fp)
    sigkey = 'TESTING456AVERYLONGKEY'
    Dspam.add_signature_tag(msg,sigkey,prob=0.99)
    self.assertTrue(msg.ismodified())
    txt,tags = Dspam.extract_signature_tags(msg.as_bytes())

    self.assertEqual(len(tags),2)
    self.assertEqual(sigkey,tags[1])
    self.assertEqual('TESTING123LONGTAG',tags[0])

def suite():
  s1 = unittest.makeSuite(pyDSpamTestCase,'test')
  s2 = unittest.makeSuite(tagTestCase,'test')
  s = unittest.TestSuite()
  s.addTest(s1)
  s.addTest(s2)
  return s

if __name__ == '__main__':
  import sys
  try:
    if len(sys.argv) > 1:
      ds = Dspam.DSpamDirectory(userdir)
      for fname in sys.argv[1:]:
        if fname == 'tag':
          s2 = unittest.makeSuite(tagTestCase,'test')
          unittest.TextTestRunner(verbosity=2).run(s2)
          continue
        print(fname)
        with open(fname,'rb') as fp:
          txt = fp.read()
          print(ds.check_spam('tonto',txt))
    else:
      unittest.main()
  finally:
    dspam.libdspam_shutdown()
