import unittest
import testdspam
import testDspam
import testcgi

def suite(): 
  s = unittest.TestSuite()
  s.addTest(testdspam.suite())
  s.addTest(testDspam.suite())
  s.addTest(testcgi.suite())
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
