# SquirrelAsAServive

This is an exploit for a 0day vulnerability in the Squirrel-VM (used by CS:GO). I found this vulnerability and wrote the exploit as part of the CyberSecurityChallengeGermany2020.

## How does it work?

I published a full writeup for the bug and exploit here: https://a2nkf.github.io/Exploiting-the-squirrel-VM/.

## Other

The expoit source code can be found in [exploit.nut](https://github.com/A2nkF/SquirrelAsAServive/blob/master/sq_exploit/exploit.nut) and the assembled version with the malicious opcodes can be found in [exploit.cnut](https://github.com/A2nkF/SquirrelAsAServive/blob/master/sq_exploit/exploit.cnut).

In order to write my exploit, I had to reverse engineer the squirrel bytecode and implement an [assembler](https://github.com/A2nkF/SquirrelAsAServive/blob/master/assembler.py) and [disassembler](https://github.com/A2nkF/SquirrelAsAServive/blob/master/disassembler.py). These are by no means full implementations, since I only implemented the functionalities I required. So while they may work on many `.cnut` files, they'll probably fail if they encounter less common instructions or types, that I didn't bother implementing :D
