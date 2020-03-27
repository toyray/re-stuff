# Point VIVISECT_ROOT to the the vivisect Github repo and add to path so that
# vtrace and the other imports work
VIVISECT_ROOT = "/path/to/vivisect"

import sys
sys.path.append(VIVISECT_ROOT)

import vtrace
from envi.archs.i386 import *   # for the architecture constants like REG_EAX

# vtrace's breakpoints only allow a string of Python code to be executed.

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

# Setup tracer
trace = vtrace.getTrace()
trace.execute('./crackme0x02')
trace.setMode("RunForever", True)

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

# Setup the second breakpoint with a callback
trace.addBreakpoint(BreakpointWithCallback(0x804844e, readPasswordFromLocalVariable))
trace.run()

