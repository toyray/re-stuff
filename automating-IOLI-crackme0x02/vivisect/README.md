# Introduction
[Vivisect](https://github.com/vivisect/vivisect) is an analysis framework for PE and ELF binaries. There isn't much documentation outside the source code, so from poking around, there appears to several tools, namely:

1. vivisect - GUI, CLI for static analysis and emulation
2. vdb - GUI debugger using Vtrace under the hood
3. vtrace - tracer framework in Python 2
4. vstruct - code for working with structures

For our purposes, we will be scripting the debugging using Vtrace for the Linux crackme.

# Usage

First, when using vtrace directly from a copy of the code from Github, setup the system path so that imports work correctly.

```python
# Point VIVISECT_ROOT to the the vivisect Github repo and add to path so that
# vtrace and the other imports work
VIVISECT_ROOT = "/path/to/vivisect"

import sys
sys.path.append(VIVISECT_ROOT)

import vtrace
```

Setting up the tracer is simple (see below).

```python
# Setup tracer
trace = vtrace.getTrace()
trace.execute('./crackme0x02')
trace.setMode("RunForever", True)
```

Setting up code to be executed on a breakpoint is a bit clunky as the code needs to be in a single string. Python supports multi-line strings so code is still readable, but as the code within the string is in a separate scope from other code in the script, any needed libraries have to be re-imported.

Once the breakpoint is created and added to the tracer with `addBreakpoint()`, call `run()` to start the debugging.

``` python
# Setup the code to be executed for the first breakpoint
readPasswordFromRegister = """
# To use the constant envi.archs.i386.REG_EAX, we would have to update system
# path for the imports to resolve, which leads to duplicate code
# 0 = GPR_A = REG_EAX
print 'Password in EAX is %d' % trace.getRegister(0)
"""

# One-time breakpoint
bp = vtrace.breakpoints.OneTimeBreak(0x8048448)
bp.setBreakpointCode(readPasswordFromRegister)
trace.addBreakpoint(bp)

trace.run()
```

To write callback-style code for breakpoints, the code below can be used (

```python
# Code below adapted from:
# https://www.limited-entropy.com/stuff/drmless.py.txt
# https://baileysoriginalirishtech.blogspot.com/2015/10/flare-on-2015-2-write-up-part-2.html
class BreakpointWithCallback(vtrace.Breakpoint):
    def __init__(self, address, callback):
        vtrace.Breakpoint.__init__(self, address)
        self.address = address
        self._cb = callback

    def notify(self, event, trace):
        self._cb(trace)

def readPasswordFromLocalVariable(trace):
    # Running this on 64 bit Linux, hence rbp, otherwise it should be ebp as
    # the crackme is 32 bit
    val = trace.readMemory(trace.parseExpression('rbp-0xc'), 4)
    # Unpack the memory contents into a signed integer
    val = struct.unpack('<I', val)[0]
    print 'Password in var_ch (EBP-0x0c) is %d' % val


# Assume tracer is already set up

# Setup the second breakpoint with a callback
trace.addBreakpoint(BreakpointWithCallback(0x804844e, readPasswordFromLocalVariable))
```

# References
- [Source code @ github.com/vivisect/vivisect](https://github.com/vivisect/vivisect) - Use the source, Luke!
- [Static analysis example @ github.com/vivisect/vivisect](https://github.com/vivisect/vivisect/wiki/Static-analysis-with-vivisect)
