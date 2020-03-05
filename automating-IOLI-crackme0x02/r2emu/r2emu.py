import r2pipe

# Create a r2pipe object for the binary that we want to emulate. Emulation does not require debugging to be enabled. 
r2 = r2pipe.open('crackme0x02.arm.exe')

# aei initializes the ESIL VM state.
r2.cmd('aei')

# aeim initializes the ESIL VM stack. The default stack address of 0x100000 and size 0xf0000 works for us so we don't specify any arguments to aeim.
r2.cmd('aeim')

# aepc sets the Program Counter to 0x00011084. For platforms that use Instruction Pointer (IP) like x86, use aeip instead.
r2.cmd('aepc 0x00011084')

# aecu continues emulation until the specified address 0x000110b8.
r2.cmd('aecu 0x000110b8')

# aer displays all registers at the current point of emulation.
# ? `aer r3`~:0[1]` can be broken as follows:
# ? `subcommand` evaluates the output of the the subcommand.
# aer r3 gets only the value of the r3 register.
# ~:0[1] greps the first row (:0) and second column ([1]) of the result of the ? command.
 
print 'Password is ' + r2.cmd('? `aer r3`~:0[1]')

# Close the r2pipe object
r2.quit()
