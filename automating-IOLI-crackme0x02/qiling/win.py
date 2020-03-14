from qiling import *
from unicorn.x86_const import *

def hook_func(ql):
   # There are no convenience functions to read registers (except IP and SP) 
   # we reach into the underlying Unicorn Engine to read the value of EAX
   print('\nPassword is %d.' % ql.uc.reg_read(UC_X86_REG_EAX))

   # Stop the emulation
   ql.uc.emu_stop()

# Setup Qiling engine to execute Windows binary with the example x86 Windows 
# rootfs provided with Qiling (in examples/rootfs/arch)

# Remember to add your DLLs and registry as per the documentation

# Emulation of Windows APIs are not complete yet so we omit the output argument
# during development to print out more information e.g. when APIs are not
# implemented
ql = Qiling(['crackme0x02.exe'],'qiling/examples/rootfs/x86_windows')

# Root privileges not required
ql.root= False

# Patch out jump to call global constructors which use APIs like FindAtomA 
# which are currently not implemented
ql.patch(0x0040148a, b'\x90\x90')

# Patch out call to scanf as it's not implemented yet and we don't care 
# for the user input
ql.patch(0x00401360, b'\x90\x90\x90\x90\x90')

# Hook 0x00401382 to callback to hook_func
ql.hook_address(hook_func, 0x00401382)

# Emulate the EXE
ql.run()
