# Introduction

Radare2 offers an emulation mode using ESIL that is handy for analyzing binaries that you can't debug natively .e.g. the ARM crackme on a Intel x86 machine running Linux.

The example script uses r2pipe to emulate execution of the password generation algorithm.

The commands in the script are the same as how you would emulate within Radare2's interactive shell.

Radare2's emulation mode currently doesn't support emulation of system and external calls, but it's still very useful for analyzing parts of encoding/decoding code.

# Usage

Create a r2pipe instance for a file *binary* using `open()`. Debugging is not required for emulation. 

```python
r2 = r2pipe.open('binary')
```

Commands for radare2 are executed using `cmd()`. Emulation commands are prefixed with `ae`, use `ae?` within Radare2's shell to read the relevant documentation.

```python
# aei initializes the ESIL VM state.
r2.cmd('aei')

# aeim initializes the ESIL VM stack. The default stack address of 0x100000 and 
# size 0xf0000 works for us so we don't specify any arguments to aeim.
r2.cmd('aeim')

# aepc sets the Program Counter to the starting address for emulation. For platforms
# that use Instruction Pointer (IP) like x86, use aeip instead.
r2.cmd('aepc start_addr')

# aecu continues emulation until the specified ending address.
r2.cmd('aecu end_addr')

# aer displays all registers at the current point of emulation. aer can also be used
# to set registers before starting the emulation
r2.cmd('aer')
```

Once you're done with the r2pipe instance, close it with `quit()`

```python
r2.quit()
```

# References
- [Emulation intro @ radare2 book](https://radare.gitbooks.io/radare2book/content/analysis/emulation.html)
- [Tutorial @ radare2 explorations book](https://monosource.gitbooks.io/radare2-explorations/content/tut3/tut3_-_esil.html)
