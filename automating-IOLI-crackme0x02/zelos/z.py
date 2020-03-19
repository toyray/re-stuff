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
