# Background
This is a collection of scripts to solve the password for a simple crackme **IOLI Crackme 0x02** from [GitHub/Maijin/Workshop2015/IOLI-crackme](https://github.com/Maijin/Workshop2015/tree/master/IOLI-crackme). 

As there are Linux (x86), Windows (x86) and PocketPC (ARM) versions of the same crackme, this is a great excuse to try out different tools :wink: and build a personal reference for automating similar RE tasks in the future.

# Static Disassembly

The important bits of the crackme are shown below. The password generation algorithm is identical for all three platforms and can be solved manually from the disassembly but what's the fun in that? :grin:

## Linux

![Disassembly of important bits](img/linux-disasm.png)

The entered password is read via *scanf()* at *0x08048426* and stored in **var_4h** as an integer. It must match the value in **eax** at *0x08048448* which is calculated by a few mathematical operations between *0x0804842B* and *0x8048444*.

## PocketPC (ARM)

![Disassembly of important bits](img/arm-disasm.png)

The entered password is read via *scanf()* at *0x00011080* and stored in **var_18h** as an integer. It must match the value in **r3** at *0x000110b8* which is calculated by a few mathematical operations between *0x00011084* and *0x000110b0*.

## Windows

![Disassembly of important bits](img/win-disasm.png)

The entered password is read via *scanf()* at *0x00401360* and stored in **var_4h** as an integer. It must match the value in **eax** at *0x00401382* which is calculated by a few mathematical operations between *0x00401365* and *0x0040137e*.

# Methods

Below are the different ways to analyse and solve this crackme. Some methods may be more optimal than others for different use cases so it helps to have various options handy.

## Debugging

1. [Debugging with Radare2 and r2pipe for Linux crackme](r2debug/)
2. [Debugging with GDB command file for Linux crackme](gdb/)
3. [Debugging with x64dbg script for Windows crackme](x64dbg/)
4. [Debugging and API hooking with WinAppDbg for Windows crackme](winappdbg/)
5. [Debugging with WinDbg and WinDbg Preview for Windows crackme](windbg/)

## Emulating

1. [Emulating with Radare2 and r2pipe for ARM crackme](r2emu/)
2. [Emulating with Unicorn for ARM and Windows crackmes](unicorn/)
3. [Emulating with Qiling for Linux and Windows crackmes](qiling/)

## Others
Miscellaneous ways (for lack of a better name ...)

1. [Solving and simplifying with Z3 for Linux and Windows crackmes](z3/) 
2. [Hooking with Frida for Linux crackme](frida/)
