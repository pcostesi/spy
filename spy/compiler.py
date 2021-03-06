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
NOP, TAG, KWORD, IDENTIFIER, NUMBER, ARROW, NEQ, OP, LB, RB, NL = range(11)
TOKEN_NAMES = "NOP TAG KWORD IDENTIFIER NUMBER ARROW NEQ OP LB RB NL".split()
_PATTERNS = (
    (re.compile(r"[ \t\f]"), NOP),
    (re.compile(r"\n"), NL),
    (re.compile(r"\["), LB),
    (re.compile(r"\]"), RB),
    (re.compile(r"[a-eA-E]([1-9][0-9]*)?"), TAG),
    (re.compile(r"[yY]|([xXzZ]([1-9][0-9]*)?)"), IDENTIFIER),
    (re.compile("#.*"), NOP),
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
    error = "No rules to match input (does not conform this grammar) \n"
    error += "At line %d, column %d" % (n_line, n_col)
    error += "\n\t%s" % line
    error += "\n" if line[-1] != "\n" else ""
    error += "\t" + "_" * (n_col - 1) + "/\\" + "_" * (len(line) - n_col - 2)
    raise SyntaxError(error)

def tokenize(input_file):
    """Tokenizes a file and yields matches in a format similar to
    generate_tokens in the stdlib module tokenize"""
    n_line = 1
    for line in input_file.readlines():
        n_col, n_stop = 0, 0
        maxcol = len(line)
        while n_col < maxcol and maxcol > 1:
            match, token = _match_some(_PATTERNS, line, n_line, n_col)
            n_col, n_stop  = match.span()
            matchline = match.string[n_col : n_stop]
            t_start, t_stop = (n_line, n_col), (n_line, n_stop)
            n_col = n_stop
        
            if token == NOP:
                continue
            yield token, t_start, t_stop, matchline
        n_line += 1


class Matcher(object):
    "Stateful matcher that keeps the lookahead and matching info"
    def __init__(self, tokens):
        self.tokens = iter(tokens)
        self.lookahead = None
        self.match()
        
    @property
    def symbol(self):
        if self.lookahead:
            return self.lookahead[3]
    
    @property
    def span(self):
        if self.lookahead:
            return self.lookahead[1][1], self.lookahead[2][1]
    
    @property
    def token(self):
        if self.lookahead:
            return self.lookahead[0]
    
    def match(self, *expect, **kwargs):
        """Matches a series of tokens (and epsilon-productions) and advances
        the token stream.
            *expect: list of expected tokens. None is the epsilon-production.
            **kwargs:
                - test: runs a test function and raises SyntaxError on false.
        Raises SyntaxError on EOF, failed tests        
        """
        try:
            self.lookahead = self.tokens.next()
        except StopIteration:
            if None not in expect:
                raise SyntaxError("Unexpected end of file")
            self.lookahead = None
            return self
            
        if not expect:
            return self
            
        for tok in expect:
            if tok == self.lookahead[0]:
                if callable(kwargs.get('test')):
                    if not kwargs['test'](self.lookahead):
                        raise SyntaxError("Failed test.")
                return self
        raise SyntaxError("Token '%s'(%s) does not match %s" % 
            (self.symbol, TOKEN_NAMES[self.token], list(TOKEN_NAMES[i] for i in expect)))
        
    
def is_kword(*kword):
    def g(token):
        if token[0] == KWORD and token[3] not in kword:
            raise SyntaxError("Keyword mismatch")
        return True
    return g
    
def equals(word):
    def g(token):
        if token[3] != word:
            raise SyntaxError("Word mismatch (got '%s' instead of '%s')" % 
                (token[3], word))
        return True
    return g
    
def valid_number(token):
    if int(token[3]) > 0:
        return True
    raise SyntaxError("Invalid number")

def _match_LB(matcher):
    matcher.match(TAG)
    tag = matcher.symbol
    matcher.match(RB).match(IDENTIFIER, KWORD, None)
    return Instruction.TAG, 0, tag

def _match_KWORD(matcher):
    if matcher.symbol == "goto":
        matcher.match(TAG)
        tag = matcher.symbol
        matcher.match(NL, LB, IDENTIFIER, KWORD, None)
        return Instruction.JMP, 0, tag
    elif matcher.symbol != "if":
        raise SyntaxError("Expected 'if' or 'goto', got %s" % matcher.symbol)
    matcher.match(IDENTIFIER)
    iden = matcher.symbol
    matcher.match(NEQ)
    matcher.match(NUMBER, test=equals("0"))
    matcher.match(KWORD, test=is_kword("goto"))
    matcher.match(TAG)
    tag = matcher.symbol
    matcher.match(NL, LB, IDENTIFIER, KWORD, None)
    return Instruction.JNZ, iden, tag

def _match_IDEN(matcher):
    iden = matcher.symbol
    matcher.match(ARROW)
        #.match(IDENTIFIER, test=equals(iden)) \
    matcher.match(IDENTIFIER, NUMBER)
    iden2 = matcher.symbol
    tok = matcher.token
    matcher.match(OP, NL, None)
    if matcher.token == OP:
        op = Instruction.INC if matcher.symbol == "+" else Instruction.DEC
        matcher.match(NUMBER, test=valid_number)
        num = int(matcher.symbol)
        matcher.match(NL, None, LB, IDENTIFIER, KWORD)
        return op, iden, num
    elif iden == iden2:
        return Instruction.NOP, iden, 0
    elif tok == NUMBER:
        return Instruction.VAR, iden, int(iden2)
    else:
        return Instruction.CPY, iden, iden2

def parse(tokens):
    "Parse a stream of tokens generated by tokenize"
    matcher = Matcher(tokens)
    while matcher.lookahead != None:
        if matcher.token == LB:
            yield _match_LB(matcher)
        elif matcher.token == KWORD:
            yield _match_KWORD(matcher)
        elif matcher.token == IDENTIFIER:
            yield _match_IDEN(matcher)
        elif matcher.token == NL:
            matcher.match(NL, LB, IDENTIFIER, KWORD, None)
        else:
            raise SyntaxError("Unexpected symbol '%s': line %d, column %d" %
                ((matcher.symbol,) + matcher.span)) 

def godel_exponents(f, no_abc=True):
    b = 0
    a = 0
    pair = lambda x, y: (2 ** x) * (2 * y + 1) - 1
    tag = lambda val: ("abcde".index(val[0].lower()) + 1) * int(val[1:] or 1)
    for op, var, val in parse(tokenize(f)):
        if op == Instruction.TAG:
            a = tag(val)
            continue
        c = 2 * int(var[1:] or 1) if var[0] != "y" else 0
        c = c - 1 if var[0] == "x" else c 
        if op == Instruction.NOP:
            b = 0
        elif op == Instruction.JNZ:
            b = tag(val) + 2
        elif op == Instruction.INC:
            b = 1
        elif op == Instruction.DEC:
            b = 2
        if no_abc:
            yield pair(a, pair(b, c))
        else:
            yield a, b, c, pair(a, pair(b, c))
        a = 0


class Compiler(object):
    def __init__(self, f, optimization=0, padding=0):
        self.f = f
        self.optimization = optimization
        self.padding = padding
        self.program = []
        
    def _translate_jumps(self):
        tags = {}
        for idx, (op, var, val) in enumerate(self.program):
            if op == Instruction.TAG:
                tags[val.lower()] = idx + 1
        for idx, (op, var, val) in enumerate(self.program):
            if op in (Instruction.JNZ, Instruction.JMP):
                self.program[idx] = op, var, tags.get(val.lower(), 0)
        
    def _translate_varnames(self):
        for idx, (op, var, val) in enumerate(self.program):
            if op not in (Instruction.TAG, Instruction.CPY):
                self.program[idx] = op, Instruction.var_to_num(var), int(val)
            elif op == Instruction.CPY:
                var1 = Instruction.var_to_num(var)
                var2 = Instruction.var_to_num(val)
                self.program[idx] = op, var1, var2

    def _translate_tags(self):
        for idx, (op, var, val) in enumerate(self.program):
            if op == Instruction.TAG:
                var = ord(val[0].lower()) - ord('a')
                val = 0 if len(val) == 1 else int(val[1:])
                self.program[idx] = op, var, val

    def tokenize(self, f=None):
        if f is None:
            f = self.f
        return tokenize(self.f)

    def parse(self, tokens=None):
        if tokens is None:
            tokens = self.tokenize()
        return parse(tokens)

    def tac(self):
        # tac takes multiple iterations to output useful code.
        # there is no need to optimize this, as programs are quite short and
        # readabilty is a plus.
        self.program = list(self.parse())
        self._translate_jumps()
        self._translate_tags()
        self._translate_varnames()
    
    def compile(self):
        self.tac()
        if self.optimization:
            self.program = dce(self.program)
            self.program = register_relocation(self.program)
        return Bytecode(Instruction(*i) for i in self.program)
        
    @classmethod
    def compile_string(cls, code):
        compiler = cls(StringIO(code))
        return compiler.compile()
