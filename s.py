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
import re

TAG = r"\s*(\[\s*(?P<tag>[a-eA-E]\d+)\s*\])?\s*"
NXT = r"(?P<nxt>[a-eA-E]\d+)"
VAR = r"([XZ]\d+)|Y"
ADD = re.compile(TAG + "(?P<var>" + VAR + r")\s*<-\s*(" + VAR + r")\s*\+\s*1")
REM = re.compile(TAG + "(?P<var>" + VAR + r")\s*<-\s*(" + VAR + r")\s*-\*1")
JNZ = re.compile(TAG + r"IF\s+(?P<var>" + VAR + r")\s*!=\s*0\s*GOTO\s*" + NXT)


class InvalidVariableNameException(Exception): pass
class InvalidTagNameException(Exception): pass
class InvalidBytecodeException(Exception): pass
class TagExistsException(Exception): pass

    
def _validate_var_name(name):
    var = name[0].lower()
    if var in ("x", "z") and name[1:].isdigit():
        num = int(name[1:])
    elif var == "y" and name[1:] == "":
        num = 1
    else:
        num = 0
    if var not in ("x", "z", "y") or num <= 0:
        raise InvalidVariableNameException("Variable %s is invalid" % name)

def _validate_tag_name(name):
    var = name[0].lower()
    num = int(name[1:]) if name[1:].isdigit() else 0
    if var not in ("a", "b", "c", "d", "e") or num <= 0:
        raise InvalidTagNameException("Variable %s is invalid" % name)


class State(object):
    """ Representation of the state tuple with convenience methods to handle
    state manupulation (avoiding corruption).
    """
    
    def __init__(self, y=0, *args, **kwargs):
        self.iptr = 1
        self.vars = defaultdict(lambda: 0)
        for i, v in enumerate(args):
            self.vars["x%d" % (i + 1)] = max(v, 0)
        for k, v in kwargs.iteritems():
            _validate_var_name(k)
            self.vars[k] = max(v, 0)

    def inc(self, var, val=1):
        _validate_var_name(var)
        self.vars[var.lower()] = self.vars[var.lower()] + val
        return self.vars[var.lower()]
        
    def dec(self, var, val=1):
        _validate_var_name(var)
        res = max(self.vars[var.lower()] - val, 0)
        self.vars[var.lower()] = res  
        return res
        
    def jnz(self, var):
        _validate_var_name(var)
        return self.vars[var.lower()] == 0
        
    def __str__(self):
        pairs = ("\t- %s:\t%s" % (k, v) for k, v in 
                                    sorted(self.vars.iteritems()))
        return "State:\n" + '\n'.join(pairs)
        
    def set(self, var, val):
        _validate_var_name(var)
        self.vars[var.lower()] = val
        
    def get(self, var):
        _validate_var_name(var)
        return self.vars[var.lower()]
        
    def update(self, **kwargs):
        for k, v in kwargs.iteritems():
            _validate_var_name(k)
            self.vars[k] = v
            
    def reset(self):
        self.vars.clear()
        self.iptr = 1
        

class BytecodeBase(object):
    """ This class contains generic data used by compilers and serializers       
        S bytecode is big-endian and has the following layout:
            * A Header _non-padded_ struct with:
                - A 4-byte unsigned integer containing the Magic
                - A 2-byte unsigned short major version
                - A 2-byte unsigned short
            * An Info _non-padded_ struct with:
                - Number of instructions in DATA section (for serialized data)
                - Number of instructions in EXEC section (the actual program)
            * An _OPTIONAL_ DATA section of _non-padded_ structs with:
                - VAR instructions
                - *ONE* terminal JMP instruction.
            * Instruction _non-padded_ structs with:
                - An unsigned char opcode
                - A 2-byte signed short representing the variable:
                    . Positive for X
                    . 0 for y
                    . Negative for Z
                - A 2-byte unsigned short with payload data:
                    For JNZ: the tag index 
    """

    LAYOUT = ">IHH"
    INSTRUCTION = ">BhH" #instruction, variable, value
    MAGIC = 0x0005C0DE #u4
    MAJOR_VERSION = 0x0001 #u2
    MINOR_VERSION = 0x0001 #u2
    INFO = ">II" # number of DATA instructions, number of EXEC instructions
    INC, DEC, JNZ, TAG, VAR, JMP = 1, 2, 3, 4, 5, 6
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
        name, idx = var[0].lower(), var[1:]
        if name == "y":
            return 0
        elif name == "x":
            return int(idx) & 0x7FFF
        else:
            return -1 * (int(idx) & 0x7FFF)
            
    def variables(self):
        return self.vars.iteritems()
        

class Bytecode(BytecodeBase):
    """ This class represents parsed Bytecode and contains serialization 
    routines
    """
           
    def __init__(self, instructions=None, state=None):
        self.program = instructions or []
        self.binary = None
        self.state = state or State()
        
    @staticmethod
    def __parse_instr(f, offset, count):
        f.seek(offset)
        INSTRUCTION_SIZE = calcsize(Bytecode.INSTRUCTION)
        instruction = 0
        while f.closed == False and instruction < count:
            data = f.read(INSTRUCTION_SIZE)
            if len(data) < INSTRUCTION_SIZE:
                raise InvalidBytecodeException("Invalid instruction size")
            op, var, val = unpack_from(Bytecode.INSTRUCTION, data)
            instruction += 1
            yield op, var, val

    def __read_bulk(self, f, offset, elems):
        for op, var, val in Bytecode.__parse_instr(f, offset, elems):
            self._add(op, var, val)
        return offset + calcsize(Bytecode.INSTRUCTION) * elems

    def from_file(self, f, ignore_state=True):
        LAYOUT_SIZE = calcsize(Bytecode.LAYOUT)
        INFO_SIZE = calcsize(Bytecode.INFO)
        
        header = f.read(LAYOUT_SIZE)
        magic, major, minor = unpack_from(Bytecode.LAYOUT, header)
        if (magic != Bytecode.MAGIC or major != Bytecode.MAJOR_VERSION or
                        minor != Bytecode.MINOR_VERSION):
            raise InvalidBytecodeException("Invalid header")
        
        info = f.read(INFO_SIZE)            
        variables, instructions = unpack_from(Bytecode.INFO, info)
        offset = LAYOUT_SIZE + INFO_SIZE
        offset = self.__read_bulk(f, offset, variables)
        offset = self.__read_bulk(f, offset, instructions)
        
    @staticmethod
    def __pack(instructions):
        for op, var, val in instructions:
            yield pack(Bytecode.INSTRUCTION, op, var, val & 0xffff)
            
    def __state_as_instructions(self):
        l = []
        for var, val in self.state.variables():
            l.append((Bytecode.VAR, Bytecode.__var_to_int(var), val))
        l.append((Bytecode.JMP, 0, self.state.iptr))
        return l
    
    def to_binary(self, save_state=False):
        state = self.__state_as_instructions() if save_state else []
        INFO = pack(Bytecode.INFO, len(state), len(self.program))
        DATA = ''.join(Bytecode.__pack(state))
        EXEC = ''.join(Bytecode.__pack(self.program))
        return Bytecode.HEADER + INFO + DATA + EXEC
        
    def _add(self, op, var, val):
        self.binary = None
        if op in (Bytecode.VAR, Bytecode.JMP):
            var = Bytecode.__int_to_var(var)
            self.state.set(var, val)
        else:
            self.program.append((op, var, val))
           

class Compiler(BytecodeBase):
    def __init__(self, f=None):
        self.program = []
        self.tags = {}
        if f:
            self.from_file(f)

    def tag(self, name):
        _validate_tag_name(name)
        name = name.lower()
        if name not in self.tags:
            # tags are no-op opcodes, so we can ignore them
            # however, adding tags is recommended for debugging and decompiling
            self.tags[name] = len(self.program) - 1 #tag this line.
            cname = Compiler._int_to_var((ord("a") + 1 - ord(name[0])))
            self.program.append((Compiler.TAG, cname, int(name[1:])))
        else:
            raise TagExistsException("Tag %s already exists" % name)
        return self
    
    def inc(self, var):
        _validate_var_name(var)
        self.program.append((Compiler.INC, var, 1))
        return self
        
    def dec(self, var):
        _validate_var_name(var)
        self.program.append((Compiler.DEC, var, 1))
        return self
        
    def jmp(self, idx):
        self.program.append((Compiler.JMP, "y", max(idx, 0)))
        return self
        
    def jnz(self, var, tag):
        _validate_var_name(var)
        _validate_tag_name(tag)
        self.program.append((Compiler.JNZ, var, tag))
        return self
        
    def __iter__(self):
        for instruction in self.program:
            op, var, val = instruction[:3]
            
            if op == Compiler.JNZ:
                val = self.tags.get(instruction[2], 0)
            yield op, Compiler._var_to_int(var), val
        
    def to_bytecode(self, state=None):
        return Bytecode(list(self), state)

    @staticmethod
    def _extract(operations, line):
        for operation, v in operations.iteritems():
            statement = re.match(operation, line)
            if statement:
                d = statement.groupdict()
                return d.get('tag', None), v, d['var'], d.get('nxt', None)

    def from_file(self, f):
        ops = {REM: Compiler.DEC, ADD: Compiler.INC, JNZ: Compiler.JNZ}
        for line in f:
            tag, op, var, nxt = Compiler._extract(ops, line)
            if tag:
                self.tag(tag)
            if op == Compiler.INC:
                self.inc(var)
            elif op == Compiler.DEC:
                self.dec(var)
            elif op == Compiler.JNZ:
                self.jnz(var, nxt)
                

def preprocessor(f):
    pass


class VM(BytecodeBase):

    def __init__(self, bytecode=None):
        self.bytecode = bytecode
    
    def step(self):
        if bytecode is None:
            return 0
            
        iptr = self.bytecode.state.iptr
        if iptr <= 0 or iptr > len(self.bytecode.program):
            return self.bytecode.state.get("y")
        
        op, var, val = self.bytecode.program[iptr - 1]
        var = VM._int_to_var(var)
        
        if op == VM.JNZ:
            if self.bytecode.state.jnz(var):
                self.bytecode.state.iptr = val
                return None
        elif op == VM.JMP:
            self.bytecode.state.iptr = val
            return None
        elif op == VM.VAR:
            self.bytecode.state.set(var, val)
        elif op == VM.INC:
            self.bytecode.state.inc(var, val)
        elif op == VM.DEC:
            self.bytecode.state.dec(var, val)
            
        self.bytecode.state.iptr += 1 

    def execute(self, **x):
        y = None
        self.bytecode.state.update(**x)
        while y is None:
            y = self.step()
        return y
        
    def state(self):
        return self.bytecode.state
                
    def load(self, f, load_state=False):
        with open(f, "rb") as input_file:
            self.bytecode = Bytecode()
            bytecode.from_file(input_file, load_state)
        return self
        
    def save(self, f, save_state=False):
        with open(f, "wb") as output_file:
            output_file.write(bytecode.to_binary())
        return self
        
    def reset(self):
        self.bytecode.state.reset()
        return self
        
# My other interpreter is less than 100 lines long.

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        state = State(sys.argv[1:])
    else:
        state = None
    
    compiler = Compiler(sys.stdin)
    bytecode = compiler.to_bytecode(state)
    vm = VM(bytecode)
    print vm.execute()
