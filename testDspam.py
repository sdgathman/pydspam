import unittest
import os
import os.path
import Dspam
import bsddb

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
      tag = Dspam.extract_signature_tags(txt)
      self.failUnless(len(tag) == 1)
      self.failUnless(db.has_key(tag[0]))
    db.close()

    spams = msgs[1:4]
    for txt in spams:
      tot = ds.add_spam('tonto',txt)		# feedback spam
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
      tot = ds.add_spam('tonto',txt)
      txt = open('test/samp1').read()	# innocent mail
      txt = ds.check_spam('tonto',txt)
      self.failIf(not txt)

    txt = open('test/spam7').read()	# spam mail
    qtxt = open(mbox).read()
    self.failUnless(qtxt.endswith(txt))

def suite(): return unittest.makeSuite(pyDSpamTestCase,'test')

if __name__ == '__main__':
  unittest.main()
