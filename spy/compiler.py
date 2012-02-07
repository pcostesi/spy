#!/usr/bin/env python
# -*- coding: utf-8 -*-
#       Copyright 2011, 2012 Pablo A. Costesich <pcostesi@alu.itba.edu.ar>
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the Dev Team nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from spy.core import Instruction, Bytecode
from spy.optimizations import register_relocation, dce
import re
from StringIO import StringIO


# This is a hand-crafted top-down parser (it's not recursive).
# Although ad-hoc, it's good enough for this project (no external dependencies) 
NOP, TAG, KWORD, IDENTIFIER, NUMBER, ARROW, NEQ, OP, LB, RB = range(10)

_patterns = (
    (re.compile(r"[ \t\f\n]"), NOP),
    (re.compile(r"\["), LB),
    (re.compile(r"\]"), RB),
    (re.compile(r"[a-eA-E]([1-9][0-9]*)?"), TAG),
    (re.compile(r"[yY]|([xXzZ]([1-9][0-9]*)?)"), IDENTIFIER),
    (re.compile("#"), NOP),
    (re.compile("<-"), ARROW),
    (re.compile(r"\+|-"), OP),
    (re.compile("!="), NEQ),
    (re.compile(r"[0-9]+"), NUMBER),
    (re.compile(r"\w+"), KWORD),
)

def _match_some(regexes, line, n_line, n_col):
    """Match patterns in order. Returns a tuple of match and token type or
    raises SyntaxError."""
    for regex, token in regexes:
        match = regex.match(line, n_col)
        if match is not None:
            return match, token
    error = "At line %d, column %d" % (n_line, n_col)
    error += "\n\t%s" % line
    error += "\t" + "_" * (n_col - 1) + "/\\" + "_" * (len(line) - n_col - 2)
    raise SyntaxError(error)

def tokenize(input_file):
    """Tokenizes a file and yields matches in a format similar to
    generate_tokens in the stdlib module tokenize"""
    n_line = 1
    for line in input_file.readlines():
        n_col, n_stop = 0, 0
        maxcol = len(line)
        
        while n_col < maxcol:
            match, token = _match_some(_patterns, line, n_line, n_col)
            n_col, n_stop  = match.span()
            matchline = match.string[n_col : n_stop]
            t_start, t_stop = (n_line, n_col), (n_line, n_stop)
            n_col = n_stop
        
            if token == NOP:
                continue
            yield token, t_start, t_stop, matchline
        n_line += 1
        



class Compiler(object):
    def __init__(self, optimization=0, padding=0)
        self.optimization = optimization
        self.padding = padding
