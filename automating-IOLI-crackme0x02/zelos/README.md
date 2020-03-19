# Introduction

[Zelos](https://github.com/zeropointdynamics/zelos) is a Python-based (3.6+) emulator for Linux binaries and supports several architectures (x86, ARM, MIPS, etc). The underlying CPU emulator is Unicorn.

This tool is similar to [Qiling](../qiling) which also runs on top of Unicorn but supports more platforms (Windows, MacOS, etc).

Personally I would prefer Zelos over Qiling for Linux emulation as the installation process is simpler and the API has better documentation.

# Usage

Code for working with breakpoints and watchpoints is written in a linear, procedural style. This is usually sufficient for simple tasks but if an event-driven approach with callbacks is preferred, try Qiling instead.

Callbacks are available for the execution, memory and syscall hooking APIs though.

This is all the code in *z.py* for solving the Linux crackme via emulation.

```python
from zelos import Zelos

# Initialize Zelos Engine
z = Zelos('crackme0x02')

# Set a one-shot temporary breakpoint
z.set_breakpoint(0x8048448, True)

# Start emulating!
z.start()

# We've hit our breakpoint. Read our password from EAX
password = z.regs.eax
print('Password in EAX is %d' % password)

# Single step
z.step()

# Read from the local variable var_ch. This should have the same value as EAX
password = z.memory.read_int(z.regs.ebp-0x0c)
print('Password at var_ch / EBP-0x0Ch is %d' % password)

# Cleanup
z.close()
```

# References
- [Official Docs @ zelos.readthedocs.io](https://zelos.readthedocs.io/en/latest/index.html)
