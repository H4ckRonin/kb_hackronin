# System Security - eCPPTv2

## Overview
Low-level system security concepts including architecture, assembly, buffer overflows, and security implementations.

**Source**: [johnermac.github.io](https://johnermac.github.io/notes/ecppt/systemsecurity/)

## Architecture

### Fundamentals

#### CPU - Central Process Unit
- Device in charge of executing the machine code of a program
- Machine code/language is the set of instructions that the CPU processes
- Each instruction is a primitive command that executes a specific operation
- Represented in hexadecimal (HEX)
- Translated to assembly language (ASM)
  - NASM - Netwide Assembler
  - MASM - Microsoft Macro Assembler

#### Instruction Set Architecture (ISA)
- Each CPU has one
- Set of instructions
- What a programmer can see: memory, registers, instructions etc
- x86 = 32-bit processors
- x64 = 64-bit processors (aka x86_64 or AMD64)

#### Registers
- The number of bits: 32 or 64 refers to the width of the CPU registers
- Think as temporary variables used by the CPU to get and store data

#### General Purpose Registers (GPRs)

| x86 naming convention | Name | Purpose |
|------------------------|------|---------|
| EAX | Accumulator | Used in arithmetic operation |
| ECX | Counter | Used in shift/rotate instruction and loops |
| EDX | Data | Used in arithmetic operation and I/O |
| EBX | Base | Used as a pointer to data |
| ESP | Stack Pointer | Pointer to the top of the stack |
| EBP | Base Pointer | Pointer to the base of the stack (aka Stack Base Pointer or Frame pointer) |
| ESI | Source Index | Used as a pointer to a source in stream operation |
| EDI | Destination | Used as a pointer to a destination in stream operation |

#### CPUs Types
- **8-bit CPU**: L = low byte, H = high byte
- **16-bit CPU**: Combines L/H and replaces with X
- **32-bit CPU**: E = means extended, used as prefix
- **64-bit CPU**: E > R = E is replaced by the R

#### Name Convention

**64-bit**: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI

**32-bit**: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI

**16-bit**: AX, CX, DX, BX, SP, BP, SI, DI

**8-bit**: AH/AL, CH/CL, DH/DL, BH/BL, SPL, BPL, SIL, DIL

#### Instruction Pointer (EIP)
- Tells the CPU where the next instruction is

#### Process Memory

```
0
Lower memory addresses
—————————————-
|.text  | - Instructions
|.data | - Initialized variable
|BSS   | - Uninitialized variable (Block Started by Symbol)
|Heap | - brk/sbrk > malloc, realloc, free = the size of the data region can be extended
|         |
|Stack | 
—————————————-
0xFFFFFFFF
Higher memory addresses
—————————————-
```

## Stack

- Last-In-First-Out = LIFO
- Think as an array used for saving a functions return addresses, passing function arguments and storing local variables
- Stack consists of logical stack frames (portions/areas of the Stack)
- Stack frames are PUSHed when calling a function and POPed when returning a value

### ESP (Stack Pointer)
- Purpose: Identify the top of the stack
- Modified each time a value is pushed in (PUSH) or popped out (POP)
- The stack grows downward, towards the lower memory addresses
- The heap grows upwards, towards the higher memory addresses

```
0 Lower Addresses | Heap >     < Stack | 0xFFFFFFFF Higher Addresses
```

### PUSH Instructions
- PUSH is executed and the ESP register is modified
- Starting Value: ESP points to the top of the stack
- Subtracts 4 (in 32-bit) or 8 (in 64-bit) from ESP

**Example**:
```
ESP points to the top of the stack -4
|A|
|B|
|C|
|D|

PUSH(E)
|E| = (it decreases by 4)
|A|
|B|
|C|
|D|
```

### POP Instructions
- Retrieves data from the top of the Stack and usually store in another register
- Process: POP is executed and the ESP register is modified (ESP +4)
- Starting Value: ESP points to the top of the stack
- Increments 4 (in 32-bit) or 8 (in 64-bit) from ESP

**Example**:
```
ESP points to the top of the stack +4
|E|
|A|
|B|
|C|
|D|

POP(E)
|A| ESP+4
|B|
|C|
|D|
```

## Stack Frame

### Functions
- **Prologue**: Sequence of instructions that take place at the beginning of a function. How the stack frames are created
- **Epilogue**: Sequence of instructions at the end of a function

The stack frame keeps track of the location where each subroutine should return the control when it terminates.

**Main operations**:
1. When a function is called, the arguments need to be evaluated
2. The control flow jumps to the body of the function, and the program executes its code
3. Once the function ends, a return is encountered, the program returns to the function call

Arguments in functions will be pushed on the stack from right to left (argc, argv)

### Prologue
When the program enters a function, the prologue is executed to create the new stack frame:
- `push ebp` = saves the old base pointer onto the stack, so it can be restored later when the function returns
- `mov ebp, esp` = copies the values of the stack pointer into the base pointer
- `sub esp, X` = The instruction subtracts X from esp. To make space for the local variables

### Epilogue
POP operation automatically updates the ESP, same as PUSH

```
-------------------
leave 
ret
-------------------
-------------------
mov esp, ebp
pop ebp
ret
-------------------
```

## Endianness

Is the way of representing (storing) values in memory. There are 3 types, the most important ones: big-endian / little-endian

### MSB - The Most Significant Bit
- In a binary number is the largest value, usually the first from the left
- The binary 100 = MSB 1

### LSB - The Least Significant
- In a binary number is the lowest value, usually the first from the right
- The binary 110 = LSB 0

### Big-endian
- LSB is stored at the highest memory address
- MSB is stored at the lowest memory address

**Example: 0x12345678**

| Highest memory | address in memory | byte value |
|----------------|-------------------|------------|
|                | +0                | 0x12       |
|                | +1                | 0x34       |
|                | +2                | 0x56       |
|                | +3                | 0x78       |
| lowest memory  |                   |            |

### Little-endian
- LSB is stored at the lowest memory address
- MSB is stored at the highest memory address

**Example: 0x12345678**

| Highest memory | address in memory | byte value |
|----------------|-------------------|------------|
|                | +0                | 0x78       |
|                | +1                | 0x56       |
|                | +2                | 0x34       |
|                | +3                | 0x12       |
| lowest memory  |                   |            |

## No Operation Instruction (NOP)

- NOP in an assembly language instruction that does nothing
- When the program encounters a NOP, it will simply skip to the next instruction
- In x86 = 0x90 - NOP are represented with the hexadecimal value
- The reason we use NOPs is to allow us to slide down to the instruction we want execute
- Buffer overflows have to match a specific size and location that the program is expecting

## Security Implementations

Overview of security implementations that have been developed to prevent or impede the exploitation of vulnerabilities such as Buffer Overflow:

- **Address Space Layout Randomization (ASLR)**
- **Data Execution Prevention (DEP)**
- **Stack Cookies (Canary)**

### ASLR
- Introduces randomness for executables, libraries and stacks in the memory address space
- Makes it more difficult for an attacker to predict memory addresses
- Causes exploits to fail and crash process

### DEP
- Is a defensive hardware and software measure that prevents the execution of code from pages in memory that are not explicitly marked as executable
- The code injected into the memory cannot be run from that region
- Makes buffer overflow exploitations even harder

### Canary
- Is a security implementation that places a value next to the return address on the stack

## Assembler Debuggers and Tools Arsenal

- Assembly is a low-level programming language consisting of a mnemonic code, also known as an opcode (operation code)

### Assembler
An assembler is a program that translates the Assembly language to the machine code.

- Microsoft Macro Assembler (MASM)
- GNU Assembler (GAS)
- Netwide Assembler (NASM)
- Flat Assembler (FASM)

### Process Assembly to Executable
When a source code file is assembled, the result file is called object file. Then a linker is needed to create the actual executable file. What linker does is take one or more object files and combine them to create the executable file.

```
ASM file > assembler > object file / static library > linker > executable
```

### Compiler
Converts high-level source code (such as C) into low-level code or directly into an object file. The end result is an executable file.

### NASM
**Resources**: https://forum.nasm.us/index.php?topic=1853.0

#### Instructions
- **Data Transfer**: MOV, XCHG, PUSH, POP
- **Arithmetic**: ADD, SUB, MUL, XOR, NOT
- **Control Flow**: CALL, RET, LOOP, Jcc (where cc is any condition)
- **Other**: STI, CLI, IN, OUT

#### Example: Sum
```
MOV EAX, 2
MOV EBX, 5
ADD EAX, EBX
---------------------
store 2 in eax
store 5 in ebx
do eax = eax + ebx
now eax contains the results
```

#### Intel vs AT&T
- **Intel (Windows)**: `MOV EAX, 8` - `<instruction><destination><source>`
- **AT&T (Linux)**: `MOVL $8, %EAX` - `<instruction><source><destination>`

The AT&T puts a percent sign (%) before registers names and a dollar sign ($) before numbers. Also adds a suffix to the instruction, which defines the operand size:
- Q (quad - 64bits)
- L (long - 32bits)
- W (word - 16 bits)
- B (byte - 8 bits)

#### More about PUSH
PUSH stores a value to the top of the stack, causing the stack to be adjusted by -4 bytes (on 32-bit systems): -0x04

```
PUSH 0x12345678 can be similar to:
---------------------------------------------------
SUB ESP, 4
MOVE [ESP], 0x12345678
---------------------------------------------------
subtract 4 to esp -> esp=esp-4
store the value 0x12345678 to the location pointed by ESP.
square brackets indicates to address pointed by the register.
```

#### More about POP
POP reads the value from the top of the stack, causing the stack to be adjusted +0x04

```
POP EAX operation can be done:
---------------------------------------------------
MOV EAX, [ESP]
ADD ESP, 4
---------------------------------------------------
store the value pointed by ESP into EAX
increment ESP by 4
```

## Buffer Overflow

Buffer overflow is a vulnerability that occurs when a program writes more data to a buffer than it can hold, causing the excess data to overflow into adjacent memory locations.

### Basic Concepts
- Buffer: A region of memory used to temporarily store data
- Overflow: Writing beyond the allocated buffer size
- Can overwrite return addresses, function pointers, and other critical data

### Exploitation Steps
1. Identify vulnerable function (strcpy, gets, sprintf, etc.)
2. Determine buffer size
3. Craft payload with:
   - NOP sled (optional)
   - Shellcode
   - Return address
4. Trigger the vulnerability

## Malware

### Malware = Malicious Software

### Techniques used by Malware
- Code injection
- Process hollowing
- DLL injection
- Rootkit techniques
- Anti-debugging
- Packing/obfuscation

### How Malware Spreads?
- Email attachments
- Malicious websites
- USB drives
- Network shares
- Social engineering

### Samples
- Viruses
- Worms
- Trojans
- Ransomware
- Spyware
- Rootkits

## Tools
- **GDB** - GNU Debugger
- **OllyDbg** - Windows debugger
- **x64dbg** - Windows debugger (64-bit)
- **IDA Pro** - Disassembler and debugger
- **Ghidra** - Reverse engineering framework
- **NASM** - Netwide Assembler
- **objdump** - Object file dumper
- **readelf** - ELF file analyzer

## Last Updated
December 2023

