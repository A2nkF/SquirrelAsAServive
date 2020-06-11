#!/usr/bin/env python3
from definitions import *
from huepy import *
from pwn import *

import struct

import exploit

DATA = None
############################### VM INFOS ###############################
SQChar_SIZE         = 0 
SQInteger_SIZE      = 0
SQFloat_SIZE        = 0
SQLineInfo_SIZE     = 0x10
SQInstruction_SIZE  = 0x8


LITERALS        = exploit.LITERALS
INSTRUCTIONS    = exploit.INSTRUCTIONS

#########################################################################
class SQFunction:
    def __init__(self, name, nliterals, ninstructions, nparameters=0, 
                 noutervalues=0, nlocalvarinfos=0, nlineinfos=0, 
                 ndefaultparams=0, nfunctions=0):
        
        self.name = name
        
        self.nliterals      = nliterals
        self.nparameters    = nparameters
        self.noutervalues   = noutervalues
        self.nlocalvarinfos = nlocalvarinfos
        self.nlineinfos     = nlineinfos
        self.ndefaultparams = ndefaultparams
        self.ninstructions  = ninstructions
        self.nfunctions     = nfunctions

        self.LITERALS       = []
        self.PARAMETERS     = [] # [b'this', b'vargv']
        self.OUTERVALUES    = [] # Prob empty
        self.LOCALVARINFOS  = [] # [(b'vargv', 1, 0, 19), (b'this', 0, 0, 19)]
        self.LINEINFOS      = [] # irrelevant?
        self.DEFAULTPARAMS  = [] # Prob empty
        self.INSTRUCTIONS   = []
        self.FUNCTIONS      = [] # just keep this empty, main is enough

    def addLiterals(self, literals):
        self.LITERALS = literals
        self.nliterals = len(self.LITERALS)
    
    def addInstructions(self, instructions):
        self.INSTRUCTIONS = instructions
        self.ninstructions = len(self.INSTRUCTIONS)

    def addLocalvarinfos(self, lvars):
        self.LOCALVARINFOS = lvars
        self.nlocalvarinfos = len(self.LOCALVARINFOS)

    def addLineinfos(self, linfos):
        self.LINEINFOS = linfos
        self.nlineinfos = len(self.LINEINFOS)


    def build(self):
        funcBuffer = bytearray()

        funcBuffer += writeType(self.name.encode(), 'OT_STRING')

        funcBuffer += TRAP

        funcBuffer += p64(len(self.LITERALS))
        funcBuffer += p64(self.nparameters)
        funcBuffer += p64(self.noutervalues)
        funcBuffer += p64(self.nlocalvarinfos)
        funcBuffer += p64(self.nlineinfos)
        funcBuffer += p64(self.ndefaultparams)
        funcBuffer += p64(len(self.INSTRUCTIONS))
        funcBuffer += p64(self.nfunctions)

        funcBuffer += TRAP

        for literal in self.LITERALS:
            funcBuffer += writeType(literal, getType(literal))
        
        funcBuffer += TRAP
        
        for param in self.PARAMETERS:
            funcBuffer += writeType(param, 'OT_STRING')
        
        funcBuffer += TRAP

        for value in self.OUTERVALUES:
            funcBuffer += p64(value[0])
            funcBuffer += writeType(value[1], 'OT_STRING') # might be wrong
            funcBuffer += writeType(value[2], 'OT_STRING') # might be wrong

        funcBuffer += TRAP

        for value in self.LOCALVARINFOS:
            funcBuffer += writeType(value[0], 'OT_STRING') # might be wrong
            funcBuffer += p64(value[1])
            funcBuffer += p64(value[2])
            funcBuffer += p64(value[3])

        funcBuffer += TRAP

        for info in self.LINEINFOS:
            assert(len(info) == SQLineInfo_SIZE)
            funcBuffer += info

        funcBuffer += TRAP

        for dparam in self.DEFAULTPARAMS:
            funcBuffer += dparam

        funcBuffer += TRAP

        for instruction in self.INSTRUCTIONS:
            funcBuffer += assemble(instruction)

        funcBuffer += TRAP

        for function in self.FUNCTIONS:
            funcBuffer += function.build()

        return funcBuffer


class SQCnut:
    def __init__(self, filename, SQChar_size=1, 
                 SQInteger_size=8, SQFloat_size=4, 
                 Stacksize=20, bggenerator=0, varparams=1):

        self.filename = filename.encode()
        self.SQChar_size = SQChar_size
        self.SQInteger_size = SQInteger_size
        self.SQFloat_size = SQFloat_size
        self.Stacksize = Stacksize
        self.Bggenerator = bggenerator
        self.Varparams = varparams

        self.ALL_FUNCTIONS = []

    def addFunction(self, function):
        self.ALL_FUNCTIONS.append(function)

    def build(self):
        outfile = open(self.filename, 'wb')
        
        outfile.write(SQ_BYTECODE_STREAM_TAG)
        outfile.write(SQ_CLOSURESTREAM_HEAD)

        outfile.write(p32(self.SQChar_size))
        outfile.write(p32(self.SQInteger_size))
        outfile.write(p32(self.SQFloat_size))

        outfile.write(TRAP)
        
        outfile.write(writeType(self.filename, 'OT_STRING'))

        for function in self.ALL_FUNCTIONS:
            outfile.write(function.build())

        outfile.write(p64(self.Stacksize))
        outfile.write(p8(self.Bggenerator))
        outfile.write(p64(self.Varparams))

        outfile.write(LIAT)

        print(good(f"Built file in {white(self.filename)}"))

def getType(literal):
    if isinstance(literal, tuple):
        return 'OT_ARRAY'
    elif literal == 'null':
        return 'OT_NULL'
    elif isinstance(literal, bytes):
        return 'OT_STRING'
    elif isinstance(literal, int):
        return 'OT_INTEGER'
    elif isinstance(literal, float):
        return 'OT_FLOAT'
    elif isinstance(literal, bool):
        return 'OT_BOOL'
    else:
        print(bad(f'Type for "{literal}" not implemented'))
        exit(-1)

def assemble(instruction):
    serialized = bytearray()

    instruction = instruction.split("] ", 2)[1]

    parts = instruction.split(":", 2)
    arg0 = int(parts[1].split(",")[0].strip(), 0x10)
    arg1 = int(parts[1].split(",")[1].strip(), 0x10)
    arg2 = int(parts[1].split(",")[2].strip(), 0x10)
    arg3 = int(parts[1].split(",")[3].strip(), 0x10)
    
    serialized += struct.pack("i", arg1)
    serialized += p8(OPS[parts[0].strip()])
    serialized += p8(arg0)
    serialized += p8(arg2)
    serialized += p8(arg3)

    return serialized


def writeType(data, SQType):
    serialized = bytearray()

    if SQType == 'OT_STRING':
        serialized += p32(TYPES[SQType])
        serialized += p64(len(data))
        serialized += data
        return serialized

    elif SQType == 'OT_INTEGER':
        serialized += p32(TYPES[SQType])
        serialized += p64(data)
        return serialized

    elif SQType == 'OT_BOOL':
        serialized += p32(TYPES[SQType])
        serialized += '\x01' if data else '\x00'
        return serialized

    elif SQType == 'OT_FLOAT':
        serialized += p32(TYPES[SQType])
        serialized += struct.pack("f", data) # TODO: fix assuming 32bit float. 
        return serialized
    
    elif SQType == 'OT_NULL':
        serialized += p32(TYPES[SQType])
        return serialized

    else:
        print(bad("'{SQType}' not implemented!"))
        exit(-1)


def main():
    if len(sys.argv) != 2:
        print(info("usage: ./assembler.py <cnut-outfile>"))
        exit(-1)

    filename = sys.argv[1]

    outfile = SQCnut(filename)

    #mainFunc = SQFunction('main', len(LITERALS), len(INSTRUCTIONS))
    mainFunc = SQFunction('', len(LITERALS), len(INSTRUCTIONS))


    # mainFunc.addLocalvarinfos([(b'i', 3, 8, 18), (b'a', 2, 7, 18), (b'vargv', 1, 0, 19), (b'this', 0, 0, 19)])

    mainFunc.addLiterals(LITERALS) 
    mainFunc.addInstructions(INSTRUCTIONS)

    outfile.addFunction(mainFunc)

    outfile.build()

if __name__ == '__main__':
    main()