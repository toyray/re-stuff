# Introduction

[Miasm](https://github.com/cea-sec/miasm) is a Python framework for assembling,
disassembling, symbolic execution and emulation on various platforms.

It's under active development, so older source code examples on the web e.g. the
ones on the Miasm blog may require some porting to work with to the current version.

The framework is also extensively tested, so the looking into the code in the `test`
directory helps when you're looking for examples of specific function calls.

# Usage

`sym_exec.py` shows how to disassemble and use the `SymbolicExecutionEngine`
to get the IR expression for the destination of the current block. It
also shows basics of working with expressions to provide a simplified context.

`emu.py` shows how to use the high-level `Sandbox` abstraction to emulate parts
of the code. `Sandbox` provides you several options out of the box which makes
debugging the emulation process easy.

# References

- [Miasm blog](https://miasm.re/blog/) - Home to several examples that really
  showcases the power of this tool
- [Advanced Binary Deobfuscation](https://github.com/malrev/ABD) - Up-to-date Miasm
scripts from the NTT Secure Platform Laboratories course, very good examples
- [Examples](https://github.com/cea-sec/miasm/tree/master/example) - Official
  examples from the Github repo
- [Extra docs](https://github.com/cea-sec/miasm/tree/master/doc) - Handy Jupyter
  Notebooks on Miasm concepts like the IR, Expressions and LocationDB

