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
from spy.core import Instruction

# Add Dead Code Elimination
def dce(program):
    "Converts unused instructions into NOP"
    used_vars = [var for op, var, _ in program if op == Instruction.JNZ] + [0]
    program2 = []
    for op, var, val in program:
        if op in (Instruction.INC, Instruction.DEC, Instruction.JNZ):
            if var not in used_vars:
                op, var, val = Instruction.NOP, 0, 0
        program2.append((op, var, val))
    return program2

# Add Instruction Reordering
    # DEC goes *before* INC, because:
    # dec, dec, dec, inc does: 1 for input x < 4, x - 2 for x >= 4
    # inc, dec, dec, dec does: 0 for input x < 3, x - 2 for x >= 3 

# Add Instruction Compression
    # between keypoints (TAGs and JNZs), compress all the INCs and DECs into
    # single instructions
    
def register_relocation(program):
    "Relocates vars to consecutive numbers"
    xstack, zstack = [], []
    program2 = []
    for op, var, val in program:
        if var != 0:
            # reordering
            stack = xstack if var > 0 else zstack
            var = abs(var)
            if var not in stack:
                stack.append(var)
            # rewriting
            var = stack.index(var) + 1
            if stack is zstack:
                var = (1 << 15) | var
        program2.append((op, var, val))
    return program2
