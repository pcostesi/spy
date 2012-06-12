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
"""
Core components of the S Language Virtual Machine:
    * Bytecode
    * Instruction
    * VM
"""

from struct import pack, pack_into, unpack, unpack_from, calcsize
from itertools import chain
from collections import defaultdict
import os
import inspect

class InvalidVariableNameException(Exception): 
    """Signals a variable is non-conformant to [xXzZ][1-9][0-9]*|y|Y"""
    pass


class InvalidTagNameException(Exception):
    """Signals a tag is non-conformant to [a-eA-E][1-9][0-9]*"""
    pass


class InvalidBytecodeException(Exception): 
    """Signals a bytecode binary has an incorrect version/cannot be parsed"""
    pass


class TagExistsException(Exception):
    """Although the S Language accepts repeated tags and only takes into
    account the first occurrence, this implementation forbids duplicated tags"""
    pass


class Instruction(object):
    LAYOUT = ">BhH" #instruction, variable, value
    SIZE = calcsize(LAYOUT)
    NOP, INC, DEC, JNZ, TAG, VAR, JMP = range(7)
    __slots__ = ("__weakref__", "__opcode", "__var", "__val")
        # You may have one Bytecode, one VM, one State... but you will probably
        # have *many* instructions (that are little more than just a tuple).
    
    def __init__(self, opcode=NOP, var=0, val=0):
        self.__opcode = opcode
        self.__var = self.var_to_num(var)
        self.__val = int(val)

    @property
    def opcode(self):
        return self.__opcode
        
    @opcode.setter
    def opcode(self, value):
        self.__opcode = value & 0xFF
        
    @property
    def var(self):
        return self.__var
        
    @var.setter
    def var(self, value):
        self.__var = self.var_to_num(value)
        
    @property
    def val(self):
        return self.__val
        
    @val.setter
    def val(self, value):
        self.__val = value & 0xFFFF 
        
    @staticmethod
    def num_to_var(var):
        """
        Takes an integer and returns an encoded variable.

        Variables
        ---------
        Variables are signed short integers:
            . Positive for X
            . 0 for y
            . Negative for Z
        There's no need for complex bit twiddling to get the index for Z. It is
        just the negative index (in two's complement).
        """
        if var == 0:
            return "y"
        elif var > 0:
            return "x%d" % var 
        else:
            return "z%d" % (var & 0xFFFF)
            
    @staticmethod
    def var_to_num(var):
        """
        Takes a string and returns an encoded integer (in two's complement).
        If the input is an int, then it returns it masked with 0xFFFF.
        """
        if isinstance(var, int):
            return var & 0xFFFF if var >= 0 else -(var & 0xFFFF)
        name, idx = var[0], var[1:]
        if name == "y" or name == "Y":
            return 0
        elif name == "x" or name == "X":
            return (int(idx) if idx != "" else 1) & 0xFFFF
        elif name == "z" or name == "Z":
            return -(int(idx) & 0xFFFF if idx != "" else 1)
        else:
            raise InvalidVariableNameException()
    
    def pack(self):
        """ Returns a string holding the binary representation of this 
        instruction.
        """
        return pack(Instruction.LAYOUT, self.opcode, self.var, self.val)
        
    def pack_into(self, buf, offset):
        """ Packs this instruction into buffer at offset bytes. This function
        is a wrapper around pack_into from the struct module.
        """
        layout = Instruction.LAYOUT
        return pack_into(layout, buf, offset, self.opcode, self.var, self.val)
        
    @classmethod
    def unpack_from(cls, buf, offset=0):
        opcode, var, val = unpack_from(cls.LAYOUT, buf, offset)
        return cls(opcode, var, val)
    
    @classmethod
    def unpack(cls, string):
        opcode, var, val = unpack(cls.LAYOUT, string) 
        return cls(opcode, var, val)

    @classmethod
    def unpack_many(cls, f, count):
        while count > 0:
            count -= 1
            yield cls.unpack(f.read(cls.SIZE))
            
    def __str__(self):
        var = Instruction.num_to_var(self.var)
        return "<Instruction %d, %s, %s>" % (self.opcode, var, self.val)
        
    def __repr__(self):
        var = Instruction.num_to_var(self.var)
        return "Instruction(%d, %s, %s)" % (self.opcode, var, self.val)
        
    def __iter__(self):
        return iter((self.opcode, self.var, self.val))


class Bytecode(object):
    """ This class contains generic data used by compilers and serializers """

    LAYOUT = ">IHH"
    MAGIC = 0x0005C0DE #u4
    MAJOR_VERSION = 0x0002 #u2
    MINOR_VERSION = 0x0001 #u2
    INFO = ">HH" # number of DATA instructions, number of EXEC instructions
    HEADER = pack(LAYOUT, MAGIC, MAJOR_VERSION, MINOR_VERSION)
    LAYOUT_SIZE = calcsize(LAYOUT)
    INFO_SIZE = calcsize(INFO)
            
    def __init__(self, instructions=None, state=None):
        self.program = list(instructions) or []
        self.state = state or State()
        
    @classmethod
    def unpack_from(cls, f, ignore_state=True):
        """ Reads binary bytecode files and reconstructs the virtual
        representation
        """
        
        header = f.read(Bytecode.LAYOUT_SIZE)
        magic, major, minor = unpack_from(Bytecode.LAYOUT, header)
        if (magic != Bytecode.MAGIC or major != Bytecode.MAJOR_VERSION or
                        minor != Bytecode.MINOR_VERSION):
            raise InvalidBytecodeException("Invalid header")
        
        info = f.read(Bytecode.INFO_SIZE)            
        n_data, n_exec = unpack_from(Bytecode.INFO, info)
        
        if ignore_state:
            state = None
            f.seek(Instruction.SIZE * n_data, os.SEEK_CUR)
        else:
            state = State.from_instructions(Instruction.unpack_many(f, n_data))
        instructions = Instruction.unpack_many(f, n_exec)
        
        return Bytecode(instructions, state)
    
    def pack(self, save_state=False):
        """ Binary representation for this bytecode """
        state = list(self.state.as_instructions()) if save_state else []
        
        INFO = pack(Bytecode.INFO, len(state), len(self.program))
        DATAEXEC = ''.join(i.pack() for i in chain(state, self.program))
        
        return Bytecode.HEADER + INFO + DATAEXEC
        
    def pack_into(self, buf, offset=0, save_state=False):
        state = list(self.state.as_instructions()) if save_state else []
        
        # HEADER
        magic = Bytecode.MAGIC
        major = Bytecode.MAJOR_VERSION
        minor = Bytecode.MINOR_VERSION
        pack_into(Bytecode.LAYOUT, buf, offset, magic, major, minor)
        offset += Bytecode.LAYOUT_SIZE
        
        # INFO
        pack_into(Bytecode.INFO, buf, offset, len(state), len(self.program))
        offset += Bytecode.INFO_SIZE
        
        # DATA + EXEC
        for i in chain(state, self.program):
            i.pack_into(buf, offset)
            offset += Instruction.SIZE
            
    def __iter__(self):
        return iter(self.program)
    
    def __str__(self):
        return "\n".join(str(i) for i in self.program)

    def __repr__(self):
        return "Bytecode([%s])" % ", ".join(repr(i) for i in self.program)


class State(object):
    """
    Representation of the state tuple with convenience methods to handle
    state manupulation (avoiding corruption).

    """

    def __init__(self, iptr=1, *args, **kwargs):
        self.iptr = iptr
        # We use a defaultdict so each time you ask for a variable
        # that hasn't been initialized, it gets added.
        self.vars = defaultdict(lambda: 0)
        
        for i, v in enumerate(args):
            self.set(i + 1, v)
        
        for k, v in kwargs.iteritems():
            self.set(k, v)

    def inc(self, var, val=1):
        key = Instruction.var_to_num(var)
        self.vars[key] += val
        return self.vars[key]
        
    def dec(self, var, val=1):
        key = Instruction.var_to_num(var)
        res = max(self.vars[key] - val, 0)
        self.vars[key] = res  
        return res
        
    def to_dict(self):
        variables = self.vars.iteritems()
        data = dict((Instruction.num_to_var(k), v) for k, v in variables)
        data['pointer'] = self.iptr
        return data
        
    def set(self, var, val):
        val = val & 0xffff
        if val < 0:
            val = 0
        self.vars[Instruction.var_to_num(var)] = val
        
    def get(self, var):
        return self.vars[Instruction.var_to_num(var)]
        
    def update(self, **kwargs):
        for k, v in kwargs.iteritems():
            self.vars[Instruction.var_to_num(k)] = v
            
    def reset(self):
        self.vars.clear()
        self.iptr = 1
    
    def as_instructions(self):
        for var, val in self.vars.iteritems():
            yield Instruction(Instruction.VAR, var, val)
        
        yield Instruction(Instruction.JMP, 0, self.iptr)
        
    @classmethod
    def from_instructions(cls, instructions):
        state = State()
        for i in instructions:
            if i.opcode == Instruction.VAR:
                state.set(Instruction.num_to_var(i.var), i.val)
            elif i.opcode == Instruction.JMP:
                state.iptr = i.val
        return state
        
    def __str__(self):
        items = self.vars.iteritems()
        variables = sorted((Instruction.num_to_var(k), v) for k, v in items)
        formatted = ("\t%s:\t%s" % pair for pair in variables)
        return ("State:\nPointer:\t%d\n" % self.iptr) + '\n'.join(formatted)



def register_opcode(opcode, self=None):
    def decorator(f):
        setattr(f, "_is_opcode", True)
        setattr(f, "_opcode", opcode)
        if self:
            self.opcodes[opcode] = f
        return f
    return decorator
    
    
class VM(object):

    def __init__(self, bytecode=None, state=None, debugger=None):
        self.bytecode = bytecode
        if state:
            self.bytecode.state = state
        self.debugger = debugger
        self.opcodes = {}
        for name, value in inspect.getmembers(self):
            if inspect.ismethod(value) and getattr(value, '_is_opcode', False):
                self.opcodes[getattr(value, '_opcode')] = value

    def step(self):
        bytecode = self.bytecode
        state = bytecode.state
        
        if bytecode is None:
            return 0
        
        iptr = state.iptr
        if iptr <= 0 or iptr > len(bytecode.program):
            return state.get(0)
        
        instruction = bytecode.program[iptr - 1]
        
        if self.debugger:
            debugger.step(vm, instruction, state)
    
        state.iptr += 1
        opcode, var, val = instruction
        try:
            self.opcodes[opcode](state, var, val)
        except KeyError:
            pass
        return None
    
    @register_opcode(Instruction.JNZ)
    def on_jnz(self, state, var, val):
        if state.get(var) != 0:
            state.iptr = val
            
    @register_opcode(Instruction.JMP)
    def on_jmp(self, state, var, val):
        state.iptr = val
            
    @register_opcode(Instruction.VAR)
    def on_var(self, state, var, val):
        state.set(var, val)
        
    @register_opcode(Instruction.INC)
    def on_inc(self, state, var, val):
        state.inc(var, val)
        
    @register_opcode(Instruction.DEC)
    def on_dec(self, state, var, val):
        state.dec(var, val)

    def execute(self, *args, **kwargs):
        value = None
        for idx, val in enumerate(args):
            self.bytecode.state.set("x%d" % (idx + 1), int(val))
        self.bytecode.state.update(**kwargs)
        
        while value is None:
            value = self.step()
        return value
        
    def save(self, path, save_state=False):
        """Save the binary bytecode to `path`, and optionally save state"""
        with open(path, "wb") as output_file:
            self.bytecode.pack_into(output_file, save_state=save_state)
        return self
        
    def reset(self):
        """Resets the state back to zero"""
        self.bytecode.state.reset()
        return self
