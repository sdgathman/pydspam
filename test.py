import unittest
import testdspam
import testDspam

def suite(): 
  s = unittest.TestSuite()
  s.addTest(testdspam.suite())
  s.addTest(testDspam.suite())
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
