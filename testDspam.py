import unittest
import os
import os.path
import Dspam
import bsddb
import mailbox
from email.Parser import Parser

userdir = 'testdir'	# test user directory

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

  def testProcess(self):
    ds = self.ds
    msgs = []
    txt = open('test/samp1').read()	# innocent mail
    msgs.append(ds.check_spam('tonto',txt))
    txt = open('test/spam7').read()	# spam mail
    msgs.append(ds.check_spam('tonto',txt))
    txt = open('test/spam8').read()	# spam mail
    msgs.append(ds.check_spam('tonto',txt))
    txt = open('test/spam44').read()	# spam mail
    msgs.append(ds.check_spam('tonto',txt))
    txt = open('test/test8').read()	# spam mail
    msgs.append(ds.check_spam('tonto',txt))

    # check that sigs are all present
    db = bsddb.btopen(ds.user_files('tonto')[1],'r')
    for txt in msgs:
      txt,tag = Dspam.extract_signature_tags(txt)
      self.failUnless(len(tag) == 1)
      self.failUnless(db.has_key(tag[0]))
    db.close()

    spams = msgs[1:4]
    for txt in spams:
      ds.add_spam('tonto',txt)		# feedback spam
      tot = ds.totals
    self.failUnless(tot == (3,2,3,0))

    # check that sigs were deleted
    dspam_dict,sigfile,mbox = ds.user_files('tonto')
    db = bsddb.btopen(sigfile,'r')
    for txt in spams:
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
      self.failIf(not txt)

    txt = open('test/spam7').read()	# spam mail

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
    self.assertEqual(msg.get('subject'),'Just another unit test')
    txt = msg.as_string()
    ds.false_positive('tonto',txt)	# feedback as false positive
    tot = ds.totals
    self.assertEqual(tot[3],1)	# should be 1 FP

    # now receive the innocent mail again, it should not look spammy anymore.
    txt = open('test/fp1').read()	# now innocent looking mail
    txt = ds.check_spam('tonto',txt)
    self.failUnless(txt)

def suite(): return unittest.makeSuite(pyDSpamTestCase,'test')

if __name__ == '__main__':
  unittest.main()
