from __future__ import print_function
import unittest
import re
import email
from email.header import decode_header
from binascii import a2b_base64

email.header.ecre = re.compile(r'''
  =\?                   # literal =?
  (?P<charset>[^?]*?)   # non-greedy up to the next ? is the charset
  \?                    # literal ?
  (?P<encoding>[qb])    # either a "q" or a "b", case insensitive
  \?                    # literal ?
  (?P<encoded>.*?)      # non-greedy up to the next ?= is the encoded string
  \?=                   # literal ?=
  (?=[ \t]|\r\n|$)      # whitespace or the end of the string
  ''', re.VERBOSE | re.IGNORECASE | re.MULTILINE)

def decode(s, convert_eols=None):
  if not s: return s
  while len(s) % 4: s += '='	# add missing padding
  dec = a2b_base64(s)
  if convert_eols:
      return dec.replace(CRLF, convert_eols)
  return dec

email.base64mime.decode = decode

class CGITestCase(unittest.TestCase):
  
  badSubj = '=?UTF-8?B?TGFzdCBGZXcgQ29sZHBsYXkgQWxidW0gQXJ0d29ya3MgQXZhaWxhYmxlAA?='

  def testDecode(self):
    ecre = email.header.ecre
    parts = ecre.split(self.badSubj)
    print(parts)
    dec = email.base64mime.decode(parts[3])
    h = decode_header(self.badSubj)
    print(h)

def suite(): return unittest.makeSuite(CGITestCase,'test')

if __name__ == '__main__':
  unittest.main()
