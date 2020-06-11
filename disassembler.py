#!/usr/bin/env python3
from definitions import *
from huepy import *
from pwn import *

import struct


DATA = None
############################### VM INFOS ###############################
SQChar_SIZE         = 0 
SQInteger_SIZE      = 0
SQFloat_SIZE        = 0
SQLineInfo_SIZE     = 0x10
SQInstruction_SIZE  = 0x8

ALL_FUNCTIONS   = []

STACKSIZE       = 0
BGGENERATOR     = 0
VARPARAMS       = 0
#########################################################################
class SQFunction:
    def __init__(self, name, nliterals, nparameters, 
                 noutervalues, nlocalvarinfos, nlineinfos, 
                 ndefaultparams, ninstructions, nfunctions):
        
        self.name = name.decode()
        
        self.nliterals      = nliterals
        self.nparameters    = nparameters
        self.noutervalues   = noutervalues
        self.nlocalvarinfos = nlocalvarinfos
        self.nlineinfos     = nlineinfos
        self.ndefaultparams = ndefaultparams
        self.ninstructions  = ninstructions
        self.nfunctions     = nfunctions

        self.LITERALS       = []
        self.PARAMETERS     = []
        self.OUTERVALUES    = []
        self.LOCALVARINFOS  = []
        self.LINEINFOS      = []
        self.DEFAULTPARAMS  = []
        self.INSTRUCTIONS   = []
        self.FUNCTIONS      = []


def parseType(expectedType=None):
    tmpType = TYPES.inv[u32(DATA.read(4))]

    # if expectedType != None and tmpType != expectedType:
    #     print(bad(f"Expected '{expectedType}' but got '{tmpType}'!"))
    #     exit(-1)

    if tmpType == 'OT_STRING':
        tmpLen = u64(DATA.read(8))
        tmpString = DATA.read(tmpLen * SQChar_SIZE)
        return tmpString

    elif tmpType == 'OT_INTEGER':
        tmpInt = u64(DATA.read(SQInteger_SIZE)) # TODO: fix assuming 64bit int. 
        return tmpInt

    elif tmpType == 'OT_BOOL':
        tmpBOOL = u64(DATA.read(SQInteger_SIZE)) # TODO: fix assuming 64bit int. 
        return True if tmpBOOL else False

    elif tmpType == 'OT_FLOAT':
        tmpFloat = struct.unpack("f", DATA.read(SQFloat_SIZE)) # TODO: fix assuming 32bit float. 
        return tmpFloat
    
    elif tmpType == 'OT_NULL':
        return 'null'

    else:
        print(bad("'{tmpType}' not implemented!"))
        exit(-1)


def parseFunction():
    tmpName = parseType('OT_STRING')
    print(good(f"Found {tmpName} function!"))

    ################## Function protos ##################
    assert(DATA.read(4) == TRAP)
    
    nliterals       = u64(DATA.read(8))
    nparameters     = u64(DATA.read(8))
    noutervalues    = u64(DATA.read(8))
    nlocalvarinfos  = u64(DATA.read(8))
    nlineinfos      = u64(DATA.read(8))
    ndefaultparams  = u64(DATA.read(8))
    ninstructions   = u64(DATA.read(8))
    nfunctions      = u64(DATA.read(8))

    tmpFunction = SQFunction(tmpName, nliterals, nparameters, noutervalues,
                            nlocalvarinfos, nlineinfos,
                            ndefaultparams, ninstructions, nfunctions)

    ################## literals ##################
    assert(DATA.read(4) == TRAP)
    for literal in range(nliterals):
        tmpFunction.LITERALS.append(parseType('OT_STRING'))

    print(good(f"Parsed {white(hex(len(tmpFunction.LITERALS)))} literals!"))

    ################## parameters ##################
    assert(DATA.read(4) == TRAP)
    for param in range(nparameters):
        tmpFunction.PARAMETERS.append(parseType('OT_STRING'))

    print(good(f"Parsed {white(hex(len(tmpFunction.PARAMETERS)))} parameters!"))

    ################## outervals ##################
    assert(DATA.read(4) == TRAP)
    for value in range(noutervalues):
        tmpType = u64(DATA.read(SQInteger_SIZE))
        tmpObject = parseType()
        tmpName = parseType()
        tmpFunction.OUTERVALUES.append((tmpType, tmpObject, tmpName))

    print(good(f"Parsed {white(hex(len(tmpFunction.OUTERVALUES)))} outervalues!"))

    ################## localvarinfos ##################
    assert(DATA.read(4) == TRAP)
    for value in range(nlocalvarinfos):
        tmpName = parseType()
        tmpPos = u64(DATA.read(SQInteger_SIZE))
        tmpStart = u64(DATA.read(SQInteger_SIZE))
        tmpEnd = u64(DATA.read(SQInteger_SIZE))
        tmpFunction.LOCALVARINFOS.append((tmpName, tmpPos, tmpStart, tmpEnd))

    print(good(f"Parsed {white(hex(len(tmpFunction.LOCALVARINFOS)))} localvarinfos!"))

    ################## lineinfos ##################
    assert(DATA.read(4) == TRAP)
    for i in range(nlineinfos):
        tmpInfo = DATA.read(SQLineInfo_SIZE)
        tmpFunction.LINEINFOS.append(tmpInfo)

    print(good(f"Parsed {white(hex(len(tmpFunction.LINEINFOS)))} lineinfos!"))

    ################## lineinfos ##################
    assert(DATA.read(4) == TRAP)
    for i in range(ndefaultparams):
        tmpInfo = u64(DATA.read(SQInteger_SIZE))
        tmpFunction.DEFAULTPARAMS.append(tmpInfo)

    print(good(f"Parsed {white(hex(len(tmpFunction.DEFAULTPARAMS)))} defaultparams!"))

    ################## instructions ##################
    assert(DATA.read(4) == TRAP)
    for i in range(ninstructions):
        tmpInfo = DATA.read(SQInstruction_SIZE)
        tmpFunction.INSTRUCTIONS.append(tmpInfo)

    print(good(f"Parsed {white(hex(len(tmpFunction.INSTRUCTIONS)))} instructions!"))

    ALL_FUNCTIONS.append(tmpFunction)

    ################## functions ##################
    assert(DATA.read(4) == TRAP)
    for i in range(nfunctions):
        parseFunction()

    print(good(f"Parsed {white(hex(len(tmpFunction.FUNCTIONS)))} functions!"))


def parseFile(filename):
    global SQChar_SIZE, SQInteger_SIZE, SQFloat_SIZE, DATA
    DATA = open(filename, 'rb')
    
    ################## HEADER ##################
    if DATA.read(2) != SQ_BYTECODE_STREAM_TAG:
        print(bad("Couln't find SQ_BYTECODE_STREAM_TAG! Invalid file"))
        exit(-1)

    if DATA.read(4) != SQ_CLOSURESTREAM_HEAD:
        print(bad("Couln't find SQ_CLOSURESTREAM_HEAD! Not little endian"))
        exit(-1)

    SQChar_SIZE     = u32(DATA.read(4))
    SQInteger_SIZE  = u32(DATA.read(4))
    SQFloat_SIZE    = u32(DATA.read(4))

    print("-------------- META DATA --------------")
    print(good(f"Using SQChar_SIZE: {SQChar_SIZE * 8}bit"))
    print(good(f"Using SQInteger_SIZE: {SQInteger_SIZE * 8}bit"))
    print(good(f"Using SQFloat_SIZE: {SQFloat_SIZE * 8}bit"))

    if DATA.read(4) != TRAP:
        print(bad("Couln't find TRAP! No function protos found"))
        exit(-1)

    filename = parseType('OT_STRING')

    print(good(f"Filename: {filename}"))
    print("---------------------------------------")

    parseFunction()

    STACKSIZE   = u64(DATA.read(SQInteger_SIZE))
    BGGENERATOR = u8(DATA.read(1))
    VARPARAMS   = u64(DATA.read(SQInteger_SIZE))

    print(good(f"Stacksize: {white(hex(STACKSIZE))}"))
    print(good(f"Bggenerator: {white(hex(BGGENERATOR))}"))
    print(good(f"Varparams: {white(hex(VARPARAMS))}"))


def disassemble(function):
    all_instructions = []

    print(f"-------------- Disassembly {white(function.name)} --------------")
    print("Literals: ", function.LITERALS)
    for i, instruction in enumerate(function.INSTRUCTIONS):
        arg1, op, arg0, arg2, arg3 = struct.unpack("iBBBB", instruction)
        op = OPS.inv[op]

        current = f"[{hex(i)}] {op}: {hex(arg0)}, {hex(arg1)}, {hex(arg2)}, {hex(arg3)}"
        all_instructions.append(current)
        print(current)

    print(function.LITERALS,
    function.PARAMETERS,
    function.OUTERVALUES,
    function.LOCALVARINFOS,
    function.LINEINFOS,
    function.DEFAULTPARAMS,
    function.INSTRUCTIONS,
    function.FUNCTIONS)
    
    return function.LITERALS, all_instructions



def main():
    if len(sys.argv) != 2:
        print(info("usage: ./disassembler.py <cnut-file>"))
        exit(-1)

    filename = sys.argv[1]
    parseFile(filename)

    for function in ALL_FUNCTIONS:
        disassemble(function)
    


if __name__ == '__main__':
    main()