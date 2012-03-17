.. image:: https://secure.travis-ci.org/pcostesi/spy.png?branch=master




SPY Language Suite
==================

Spy is an implementation of the language presented in Computability, Complexity and Languages by Martin D. Davis and Elaine J. Weyuker.
I started this project in order to learn about compilers, parsers and languages, as well as virtual machines and optimizations. As such, this project is not intended for production and is more like a research project.




About the Bytecode
==================
S bytecode has been designed with portability and ease of implementation even in low-level languages. It is a big-endian binary file that stores both the program and optionally a snapshot.




Layout
------

::
  Fig. 1: A minimal bytecode layout
       ____ __ __    ____ ____    _ __ __     _ __ __    _ __ __     _ __ __
      |____|__|__|  |____|____|  |_|__|__|...|_|__|__|  |_|__|__|...|_|__|__|
       MAGI MA MI    DATA EXEC     VAR 1        JMP       INST 1     INST N
      \__________/  \_________/  \___________________/  \___________________/
         HEADER         INFO          DATA Section           EXEC Section
      \_______________________/  \__________________________________________/
              Metadata                           Instructions


S bytecode is big-endian and has the following layout:

  - A Header non-padded struct with:
      - A 4-byte unsigned integer containing the Magic
      - A 2-byte unsigned short major version
      - A 2-byte unsigned short (minor version)
  - An Info non-padded struct with:
      - Number of instructions in DATA section (for serialized data) as a 4-byte unsigned integer.
      - Number of instructions in EXEC section (the actual program) as a 4-byte unsigned integer.
  - An _OPTIONAL_ DATA section of non-padded structs with:
    - VAR instructions
    - *ONE* terminal JMP instruction.
  - An _OPTIONAL_ EXEC section of non-padded structs with:
    - An unsigned char opcode
    - A 2-byte signed short representing the variable:
      - Positive for X
      - 0 for y
      - Negative for Z
    - A 2-byte unsigned short with payload data:
      - For JNZ: an absolute index for the next instruction
  - An optional EXTRA section. No special requirements are made regarding this section, except that it must be big-endian and safefly ignored by virtual machines.



Metadata Section
----------------

"Magic" (MAGI) is an arbitrary integer that identifies S bytecode. It also prevents unsafe handling of strings in C code, as the first bytes will serve as NUL terminators.

Major (MA) and Minor (MI) version numbers identify the bytecode version. As a norm, changes that break existing instruction semantics increment the major version number, while new instructions that can be safely ignored (such as debugging instructions, VM signaling, NOP) or EXTRA sections added at the end of the file.

The INFO section contains the length of the DATA and EXEC sections. This allows linear parsers to allocate memory and set logic boundaries between DATA, EXEC and EXTRA.


Instructions Section
--------------------

The DATA and EXEC sections are technically a single section containing bytecode opcodes and parameters. However, both sections have different purposes:
The DATA section contains the state of a running program, and it comes before the EXEC section so a linear VM can pre-load (and jump to the appropiate instruction) before running the program. This section can be of zero size. 
The recommended layout of this section is to place only VAR instructions and a final JMP instruction, although it is possible to use any instruction here (so using any instruction other than VAR and JMP in this section are undefined behaviour).
The EXEC section contains the program itself. Any instruction may be used here, although it is strongly discouraged to use VAR and JMP instructions (as those are not part of the S Language itself and alter the behaviour of the program, and are left as undefined behaviour).
Ancillary Section

Finally, the EXTRA section is not mandatory and may contain any data. The purpose of this section is to add information about the program such as original source code, author and even another program. This section runs for the rest of the length of the file. The only two restrictions are that it must be big-endian and must be safely ignored.


Instructions
------------

Instructions are comprised by an opcode and two parameters (the first usually the variable, the second a positive value).


Variables
---------

Variables are signed short integers:

  - Positive for X
  - 0 for y
  - Negative for Z

There's no need for complex bit twiddling to get the index for Z. It is just the negative index (in two's complement).


Instruction Table
-----------------

+--------------------+------+--------+-----------+-----------------------------+---------+
| Instruction        | Word | Opcode | Parameter | Value                       | Virtual |
+====================+======+========+===========+=============================+=========+
| No operation       | NOP  | 0      |           |                             | Yes     |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Increment variable | INC  | 1      | Variable  | Unsigned Short (0 to 65535) | No      |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Decrement variable | DEC  | 2      | Variable  | Unsigned Short (0 to 65535) | No      |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Jump if variable   | JNZ  | 3      | Variable  | Instruction offset as an    | No      |
| is not zero        |      |        |           |                             |         |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Tag                | TAG  | 4      | 1 for A,  | Unsigned Short (0 to 65535) | Yes     |
|                    |      |        | 2 for B,  | 0 means halt.               |         |
|                    |      |        | ...,      |                             |         |
|                    |      |        | 5 for E   | Unsigned Short (0 to 65535) |         |
|                    |      |        |           | indicating the tag index.   |         |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Set Variable       | VAR  | 5      | Variable  | Unsigned Short (0 to 65535) | No      |
|                    |      |        |           | as value.                   |         |
+--------------------+------+--------+-----------+-----------------------------+---------+
| Unconditional Jump | JMP  | 6      |           | Program Counter as Unsigned | No      |
|                    |      |        |           | Short (0 to 65535)          |         |
+--------------------+------+--------+-----------+-----------------------------+---------+


Both jumps use absolute addressing, starting at the beginning of the EXEC section.



Dependencies
============
  - Python >=2.6
  - nose (for testing)




License
=======

New BSD
