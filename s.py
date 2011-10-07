#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       s.py
#
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


from collections import defaultdict
from struct import pack, unpack_from, calcsize

class InvalidVariableNameException(Exception): pass
class InvalidTagNameException(Exception): pass
class InvalidBytecodeException(Exception): pass
class TagExistsException(Exception): pass

    
def __validate_var_name(name):
    var = name[0].lower()
    if var in ("x", "z") and name[1:].isdigit():
        num = int(name[1:])
    elif var == "y" and name[1:] == "":
        num = 1
    else:
        num = 0
    if var not in ("x", "z", "y") or num <= 0:
        raise InvalidVariableNameException("Variable %s is invalid" % name)

def __validate_tag_name(name):
    var = name[0].lower()
    num = int(name[1:]) if name[1:].isdigit() else 0
    if var not in ("a", "b", "c", "d", "e") or num <= 0:
        raise InvalidTagNameException("Variable %s is invalid" % name)


class State(object):
    """ Representation of the state tuple with convenience methods to handle
    state manupulation (avoiding corruption).
    """
    
    def __init__(self, y=0, **kwargs):
        self.iptr = 1
        self.vars = defaultdict(lambda: 0)
        for k, v in kwargs.iteritems():
            __validate_var_name(k)
            self.vars[k] = v

    def inc(self, var):
        __validate_var_name(var)
        self.vars[var.lower()] = self.vars[var.lower()] + 1
        return self.vars[var.lower()]
        
    def dec(self, var):
        __validate_var_name(var)
        val = max(self.vars[var.lower()] - 1, 0)
        self.vars[var.lower()] = val  
        return val
        
    def jnz(self, var):
        __validate_var_name(var)
        return self.vars[var.lower()] == 0
        
        def __str__(self):
            pairs = ("\t- %s:\t%s" % (k, v) for k, v in 
                                        sorted(self.vars.iteritems()))
            return "State:\n" + '\n'.join(pairs)


class BytecodeBase(object):
    """ This class contains generic data used by compilers and serializers       
        S bytecode is big-endian and has the following layout:
            * A Header _non-padded_ struct with:
                - A 4-byte unsigned integer containing the Magic
                - A 2-byte unsigned short major version
                - A 2-byte unsigned short
            * Instruction _non-padded_ structs with:
                - An unsigned char opcode
                - A 2-byte signed short representing the variable:
                    . Positive for X
                    . 0 for y
                    . Negative for Z
                - A 2-byte unsigned short representing the jump offset from
                  the start of the Instruction section
    """

    LAYOUT = ">IHH"
    INSTRUCTION = ">BhH" #instruction, variable, value
    MAGIC = 0x0005C0DE #u4
    MAJOR_VERSION = 0x0001 #u2
    MINOR_VERSION = 0x0000 #u2
    INC, DEC, JNZ, TAG, VAR = 1, 2, 3, 4, 5
    HEADER = pack(LAYOUT, MAGIC, MAJOR_VERSION, MINOR_VERSION)
    
    @staticmethod
    def _int_to_var(var):
        if var == 0:
            return "y"
        elif var > 0:
            return "x%d" % var
        else:
            return "z%d" % -var
            
    @staticmethod
    def _var_to_int(var):
        name, idx = var[0].lower(), int(var[1:]) & 0x7FFF
        if name == "y":
            return 0
        elif name == "x":
            return idx
        else:
            return -idx
        

class Bytecode(BytecodeBase):
    """ This class represents parsed Bytecode and contains serialization 
    routines
    """
           
    def __init__(self, instructions=None):
        self.program = instructions or []
        
    @staticmethod
    def __parse_instr(f, offset):
        INSTRUCTION_SIZE = calcsize(Bytecode.INSTRUCTION)
        while f.closed == False:
            data = f.read(INSTRUCTION_SIZE)
            if len(data) < INSTRUCTION_SIZE:
                raise InvalidBytecodeException("Invalid instruction size")
            op, var, val = unpack_from(Bytecode.INSTRUCTION, f, offset)
            offset += INSTRUCTION_SIZE
            yield op, Bytecode._int_to_var(var), val

    def from_file(self, f, skip_opcodes=[BytecodeBase.VAR]):
        LAYOUT_SIZE = calcsize(Bytecode.LAYOUT)
        
        magic, major, minor = unpack_from(Bytecode.LAYOUT, f)
        if (magic != Bytecode.MAGIC or major != Bytecode.MAJOR_VERSION or
                        minor != Bytecode.MINOR_VERSION):
            raise InvalidBytecodeException("Invalid header")
        self.program = [i for i in Bytecode.__parse_instr(f, LAYOUT_SIZE)
                if i not in skip_opcodes]
        
    def to_binary(self, skip_opcodes=[BytecodeBase.VAR]):
        instructions = (i for i in self.program if i[0] not in skip_opcodes)
        packed = (pack(Bytecode.INSTRUCTION, *i) for i in instructions)
        return Bytecode.HEADER + ''.join(packed)
        

class Compiler(BytecodeBase):
    def __init__(self):
        self.program = []
        self.tags = {}

    def tag(self, name):
        __validate_tag_name(name)
        name = name.lower()
        if name not in self.tags:
            self.tags[name] = len(self.program) #tag the NEXT line.
            self.program.append((Compiler.TAG, 0, name))
        else:
            raise TagExistsException("Tag %s already exists" % name)
    
    def inc(self, var):
        __validate_var_name(var)
        self.program.append((Compiler.INC, var))
        
    def dec(self, var):
        __validate_var_name(var)
        self.program.append((Compiler.DEC, var))
        
    def jnz(self, var, tag):
        __validate_var_name(var)
        __validate_tag_name(tag)
        self.program.append((Compiler.JNZ, var, tag))
        
    def instructions(self, skip_opcodes=[BytecodeBase.VAR]):
        program = (i for i in self.program if i not in skip_opcodes)

        for instruction in program:
            op, var = instruction[0], Compiler._var_to_int(instruction[1])
            
            if len(instruction) == 3:
                val = self.tags.get(instruction[2], 0)
            else:
                val = 0
            yield op, var, val
        
    def to_bytecode(self, skip_opcodes=[BytecodeBase.VAR]):
        return Bytecode(list(self.instructions(skip_opcodes)))

    def from_tokens(self, tokens):
        pass

def preprocessor(f):
    pass

def tokenize_file(f):
    return [
        (Bytecode.TAG, "a1"),
        (Bytecode.INC, "x1"),
        (Bytecode.DEC, "x1"),
        (Bytecode.JNZ, "x1", "a1")
    ]


class VM(object):

    def __init__(self, f, state=None):
        self.state = state or State()
    
    def step(self):
        iptr = self.state.iptr

    def execute(self):
        pass
                
    def load(self, f):
        pass
        
    def save(self, f):
        pass
