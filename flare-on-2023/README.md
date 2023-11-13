## Introduction

This is a selection of scripts I wrote for Flare-On 10 (2023) that could be
repurposed for similar malware analysis tasks in the future.

I've also documented the design rationale and implementation details (mainly as
a reference for future me :smiley:)

## Challenge 05

This adapts the reconstruction script written for challenge 13 to work on a
shellcode blob instead of a PE file.

[View scripts](ch05/)

## Challenge 08

This contains a pair of scripts to extract TCP requests to a C2 server from a PCAP and
replay those requests to a live C2 server.

[View scripts](ch08/)

## Challenge 12

This contains two scripts, one to disassemble the code blob executed by the
Hyper-V virtual processor via the Windows Hypervisor Platform APIs and another to
emulate and patch the instruction bytes decrypted at runtime.

[View scripts](ch12/)

## Challenge 13

This contains a script to reconstruct the original binary to remove the
JMP-based obfuscation and any duplicate code blocks for a saner static code
analysis experience.

[View scripts](ch13/)
