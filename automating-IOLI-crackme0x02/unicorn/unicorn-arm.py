from unicorn import *
from unicorn.arm_const import *

# Code to be emulated as extracted from the PocketPC binary (0x38 bytes from 0x011084)
ARM_CODE = b"\x5a\x30\xa0\xe3\x14\x30\x0b\xe5\x7b\x3f\xa0\xe3\x10\x30\x0b\xe5\x14\x20\x1b\xe5\x10\x30\x1b\xe5\x03\x30\x82\xe0\x14\x30\x0b\xe5\x14\x20\x1b\xe5\x14\x30\x1b\xe5\x92\x03\x03\xe0\x10\x30\x0b\xe5\x18\x20\x1b\xe5\x10\x30\x1b\xe5"

# Define starting address for code execution
CODE_ADDRESS = 0x100000

# Define starting address for stack memory
STACK_ADDRESS = 0xF00000
STACK_SIZE = 0x1000

# Stack pointer needs to be within memory allocated for it so we
# point it to the middle of the stack memory. Important if we have 
# multiple stack frames from calling multiple functions
STACK_POINTER_ADDRESS = STACK_ADDRESS + (STACK_SIZE / 2)

# Initialize emulator in ARM mode
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

# Map 1MB and 1000 bytes memory for code and stack respectively.
# For simple emulation, if we have the stack address within the memory
# mapped for the code, we need to call mem_map only once
mu.mem_map(CODE_ADDRESS, 2 * 1024 * 1024)
mu.mem_map(STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
 
# Write our code to the code address
mu.mem_write(CODE_ADDRESS, ARM_CODE)

# Initialize machine registers. EBP needs to have a value as it's used for
# local variables
mu.reg_write(UC_ARM_REG_FP, STACK_POINTER_ADDRESS)
 
# Emulate code
mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(ARM_CODE))
 
# Read the value of R3
r_r3 = mu.reg_read(UC_ARM_REG_R3)
print("Password in R3 = %d" % r_r3)
