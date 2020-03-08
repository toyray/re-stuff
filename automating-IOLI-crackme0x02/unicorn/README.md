# Introduction
[Unicorn](http://www.unicorn-engine.org/) is a very useful tool for programmatically emulating sections of code and is available for multiple platforms (Windows, Linux, MacOS, etc).

For simple tasks, Radare2's emulation mode (demonstrated [here](../r2emui)) is usually sufficient but Unicorn is really powerful for more complicated use cases.

The example scripts show Unicorn's x86 and ARM emulation (nearly identical with superficial changes for architectural differences) on a Linux system.

If you intend to only use the Python bindings, installation on Linux and MacOS can be done with `sudo pip install unicorn`. Windows users can download a precompiled binary at the homepage.

# Usage

Setting up Unicorn involves the following steps:

1. Initialize the Unicorn engine with the correct architecture and mode.

```python
from unicorn import *
from unicorn.x86_const import *

# Initialize emulator in X86-32bit mode
mu = Uc(UC_ARCH_X86, UC_MODE_32)
```

2. Mapping memory (RWX by default) for code. Mapping memory for stack, heap only if required (not shown here, please see example scripts).

```python
# Define starting address for code execution
CODE_ADDRESS = 0x100000

# Map 2MB of memory for code (and stack)
mu.mem_map(CODE_ADDRESS, 2 * 1024 * 1024)
```

3. Writing code to mapped memory. An easy way to extract code via Radare2 is to run `r2 crackme0x02.exe -qc "pcs 0x20 @0x401365 > emu-code"` which will output 32 bytes of instructions from the address 0x401365 prefixed with *\x* to the file emu-code.

```python
# Code to be emulated
X86_CODE32 = b"\xc7\x45\xf8\x5a\x00\x00\x00\xc7\x45\xf4\xec\x01\x00\x00\x8b\x55\xf4\x8d\x45\xf8\x01\x10\x8b\x45\xf8\x0f\xaf\x45\xf8\x89\x45\xf4"

# Write our code to the code address
mu.mem_write(CODE_ADDRESS, X86_CODE32)
```

4. Setting up initial register state.

```python
# Initialize machine registers. EBP needs to have a value as it's used for
# local variables
STACK_ADDRESS = 0x110000
mu.reg_write(UC_X86_REG_EBP, STACK_ADDRESS)
```

5. Setting up any hooks (not used in example scripts).

6. Emulate!

```python
# Start emulating all 32 bytes of instructions
mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE32))
```

7. Read any register or memory locations required.

```python
# Read the value of EAX
r_eax = mu.reg_read(UC_X86_REG_EAX)
```

# References
- [Official tutorial @ www,unicorn-engine.org](http://www.unicorn-engine.org/docs/tutorial.html) - Example scripts in Python and C
- [Python source code @ github.com/unicorn-engine/unicorn](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python/bindings) - Source code for the Python bindings. Useful for looking up the constants.
