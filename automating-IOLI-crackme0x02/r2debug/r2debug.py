import r2pipe

# Open the process in Radare2 (enabling debugging mode using -d flag is optional when using rarun2 via dbg.profile)
r2 = r2pipe.open('crackme0x02', flags=['-d'])

# Use a rarun2 profile so that we can supply a fake password via stdin to the scanf call @ 0x8048426. If program requires no input, the rarun2 profile is not needed
r2.cmd('e dbg.profile=crackme0x02.rr2')

# Reload process for debugging (this is not needed if we opened process in debugging mode and did not use a rarun2 debug profile)
r2.cmd('ood')

# Run the same commands that you would have done interactively in the radare2 shell

# db 0x08048448 creates a breakpoint at 0x8048448, where we want to get the value of EAX
r2.cmd('db 0x08048448')

# dc continues execution until our breakpoint is hit
r2.cmd('dc')

# '? `dr~eax[1]:0`~uint32[1]" extracts the value in EAX and converts it to an unsigned integer.
# Detailed breakdown of command as follows:

# "? `sub-command`~uint32[1]" gets the value returned by the subcommand as an unsigned integer (which is the value of the password)
# 1. ? evaluates the value of an expression. In this case the expression is the output of the subcommand enclosed within the `` marks
# 2. ~uint32 greps the output lines containing uint32
# 3. [1] extracts only the second column

# dr~eax:0[1] gets the value in EAX
# 1. dr prints out the values of the registers
# 2. ~eax greps the output lines containing 'eax'
# 3. :0 extracts only the first row
print "Password is " + r2.cmd('? `dr~eax[1]:0`~uint32[1]"')

# Cleanup up the r2pipe instance
r2.quit()
