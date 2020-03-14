from qiling import *
from unicorn.x86_const import *

def hook_func(ql):
   # There are no convenience functions to read registers (except IP and SP) 
   # we reach into the underlying Unicorn Engine to read the value of EAX
   print('Password is %d.' % ql.uc.reg_read(UC_X86_REG_EAX))

   # Stop the emulation
   ql.uc.emu_stop()

# Setup Qiling engine to execute Linux ELF with the example x86 Linux rootfs 
# provided with Qiling (in examples/rootfs/arch)

# The default output is strace/ltrace but we don't need those here
ql = Qiling(['crackme0x02'],'qiling/examples/rootfs/x86_linux', output='off')

# Root privileges not required
ql.root= False

# Hook 0x08048448 to callback to hook_func
ql.hook_address(hook_func, 0x08048448)

# Emulate the ELF
ql.run()
