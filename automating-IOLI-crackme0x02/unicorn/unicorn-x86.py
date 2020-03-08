from unicorn import *
from unicorn.x86_const import *

# Code to be emulated as extracted from the Windows binary (0x20 bytes from 0x401365)
X86_CODE32 = b"\xc7\x45\xf8\x5a\x00\x00\x00\xc7\x45\xf4\xec\x01\x00\x00\x8b\x55\xf4\x8d\x45\xf8\x01\x10\x8b\x45\xf8\x0f\xaf\x45\xf8\x89\x45\xf4"

# Define starting address for code execution
CODE_ADDRESS = 0x100000

# Define starting address for stack memory
STACK_ADDRESS = 0xF00000
STACK_SIZE = 0x1000

# Stack pointer needs to be within memory allocated for it so we
# point it to the middle of the stack memory. Important if we have 
# multiple stack frames from calling multiple functions
STACK_POINTER_ADDRESS = STACK_ADDRESS + (STACK_SIZE / 2)

# Initialize emulator in X86-32bit mode
mu = Uc(UC_ARCH_X86, UC_MODE_32)
 
# Map 1MB and 1000 bytes memory for code and stack respectively.
# For simple emulation, if we have the stack address within the memory
# mapped for the code, we need to call mem_map only once
mu.mem_map(CODE_ADDRESS, 2 * 1024 * 1024)
mu.mem_map(STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
 
# Write our code to the code address
mu.mem_write(CODE_ADDRESS, X86_CODE32)

# Initialize machine registers. EBP needs to have a value as it's used for
# local variables
mu.reg_write(UC_X86_REG_EBP, STACK_POINTER_ADDRESS)
 
# Emulate code
mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE32))
 
# Read the value of EAX
r_eax = mu.reg_read(UC_X86_REG_EAX)
print("Password in EAX = %d" % r_eax)
