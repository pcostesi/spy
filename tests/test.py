#!/usr/bin/env python

import os
import sys
sys.path.insert(0, os.path.abspath('..'))

import unittest
from spy.compiler import tokenize
from StringIO import StringIO

class TestTokenizer(unittest.TestCase):
    
    def test_should_accept_a_valid_token_sequence(self):
        source = """[A][[<-]\t\nE1x1000-   <-!=-+yz100]#$"""
        f = StringIO(source)
        tokens = tokenize(f)
        self.assertIsNotNone(list(tokens))
        
    def test_should_raise_SyntaxError_on_invalid_token_sequence(self):
        source = """->\t\n$"""
        with self.assertRaises(SyntaxError):
            list(tokenize(StringIO(source)))

if __name__ == '__main__':
    unittest.main()
