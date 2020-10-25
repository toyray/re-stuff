# Introduction

This is a selection of hacky techniques that worked for me for Flare-On 7.

I try to illustrate them in detail, while they're not the ideal way to attack the
challenges but may be useful in other contexts.

There are some parts of the challenges that I want to explore further in the
upcoming months and will link them here when I get to them.

## Challenge 10

Challenge 10 is a 32 bit Linux ELF and has anti-debugging protection for
*some* of the processes. Due to some bad assumptions on my end, I ended up with
some really hacky ways to get through part 2 and 3.

1. [Part 1a](ch10/part1a.md) - Adding structs in IDA Pro
2. [Part 1b](ch10/part1b.md) - Patching library calls in Radare2
3. [Part 2](ch10/part2.md) - Patching in Radare2 to print dynamically-generated
   data
4. [Part 3](part3.md) - Debugging specific functions in shellcode in x32dbg on
   Windows (HACKY!!!)
