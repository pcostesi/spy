#!/usr/bin/env python
# -*- coding: utf-8 -*-
#       Copyright 2011 Pablo Alejandro Costesich <pcostesi@alu.itba.edu.ar>
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
from spy.compiler import parse, tokenize


def ffs(n):
    x = 1
    while n % 2 == 0 and n > 0:
        n /= 2
        x += 1
    return x
        
# BEGIN HACK (just because we need speed)
try:
    import ctypes
    libc = ctypes.cdll.LoadLibrary('libc.so.6')
    ffs = libc.ffs
except:
    pass
# END HACK


def _extract_tags(instructions):    
    # we should have a better handling of jump ladders.
    # we could have many tags one after another, or separated by NOPs. Those
    # may be handled as synonyms and optimize the output.
    tags = {}
    jumps = {}
    exit = "e"
    length = 0
    
    for idx, (op, var, val) in enumerate(instructions):
        if op == Instruction.TAG:
            name = chr(var + ord("a"))
            if val:
                name += str(val)
            tags[idx + 1] = name
        elif op == Instruction.JNZ:
            jumps[idx + 1] = val
        length = idx + 1
    
    for start, end in jumps.iteritems():
        if start not in tags and 0 < end < length:
            tags[start] = "a" + str(end)
    
    i = 0
    while exit in tags.items():
        i += 1
        exit = "e" + str(i)
    
    return tags, exit

def rebuild_ast(instructions):
    tags, exit = _extract_tags(instructions)
    for idx, (op, var, val) in enumerate(instructions):
        if op == Instruction.TAG:
            yield (op, None, tags[idx + 1])
        elif op in (Instruction.INC, Instruction.DEC):
            yield (op, Instruction.num_to_var(var), str(val))
        elif op == Instruction.JNZ:
            yield (op, Instruction.num_to_var(var), tags.get(idx + 1, exit))
            
def rebuild_lines(ast):
    tag = ""
    for op, var, val in ast:
        if op == Instruction.TAG:
            tag = "[" + val.upper() + "]"
            continue
        elif op == Instruction.JNZ:
            line = "if %s != 0 goto %s" % (var, val.upper())
        elif op == Instruction.INC:
            line = "%s <- %s + %s" % (var, var, val)
        elif op == Instruction.DEC:
            line = "%s <- %s - %s" % (var, var, val)
        elif op == Instruction.NOP:
            line = "%s <- %s" % (var, var)
        yield tag + "\t" + line
        tag = ""
        
def decompile(bytecode, ast=None):
    if ast is None:
        ast = rebuild_ast(bytecode)
    lines = rebuild_lines(ast)
    return '\n'.join(lines)

def ipair(n):
    n += 1
    a = ffs(n) - 1
    b = (n / (2 ** a) - 1) / 2
    return a, b
    
def rebuild_godel_ast(l):
    tag = lambda x: "abcde"[(x - 1) % 5] + str(x / 5 + 1)
    for n in l:
        a, x = ipair(n)
        b, c = ipair(x)
        var = "x" if c % 2 == 1 else "z"
        var = "y" if c == 0 else var + str((c + 1) / 2) 
        if a != 0:
            yield (Instruction.TAG, None, tag(a))
        if b == 0:
            yield (Instruction.NOP, var, None)
        elif b == 1:
            yield (Instruction.INC, var, 1)
        elif b == 2:
            yield (Instruction.DEC, var, 1)
        else:
            yield (Instruction.JNZ, var, tag(c))
        
def decompile_godel_exponents(l):
    return decompile(None, rebuild_godel_ast(l))
        
def format(f):
    return '\n'.join(rebuild_lines(parse(tokenize(f))))
