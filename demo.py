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

from spy.core import VM
from spy.compiler import Compiler
from spy.decompiler import decompile
from StringIO import StringIO

f = StringIO("""
[B42] if x1 != 0 goto E
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
 z1 <- z1 + 1
    [E90] z10 <- z10 + 1
    y <- y + 1
    """)
    
compiler = Compiler(f, True)
bytecode = compiler.compile()

pcode = Compiler.compile_string("[A] y <- y + 300")

vm = VM(bytecode)
print vm.execute(2)
print VM(pcode).execute()
print decompile(bytecode)
