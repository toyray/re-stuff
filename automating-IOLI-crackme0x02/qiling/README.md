# Introduction

[Qiling](https://www.qiling.io/) is a high level emulation framework for executables (PE EXE, ELF, etc) built on top of Unicorn Engine. It supports a variety of architectures (e.g. x86, ARM, MIPS, etc) and platforms (e.g Linux, Windows, FreeBSD, etc)  although not all platforms are fully implemented at the moment. Linux emulation is definitely better supported than Windows emulation at the momenti :grin:.

For those better supported platforms, it's a faster way than using Unicorn directly to emulate chunks of code. Otherwise Unicorn is still a good option (see the equivalent solution with Unicorn [here](../unicorn)

# Usage

Install using the [official instructions](https://github.com/qilingframework/qiling/blob/master/docs/SETUP.md). Python 3 worked for emulating Linux; Python 3.6+ is required for Windows emulation due to usage of some 3.6-specific Python features. There's also an option to spin up a Docker container for less hassle.

For Windows emulation, DLLs and registry hives from a Windows machine is required. The quickest way to collect the necessary files is to run their [CI script](https://github.com/qilingframework/qiling/blob/master/examples/scripts/dllscollector.bat) within a Administrative Command Prompt and then copy the files over.

Once everything is installed correctly, usage is very simple. The following code is the bare minimum to solve the Linux crackme. The script for the Windows crackme is slightly longer to patch out calls to unemulated APIs.

```python
from qiling import *
from unicorn.x86_const import *

def hook_func(ql):
   # There are no convenience functions to read registers (except IP and SP) 
   # we reach into the underlying Unicorn Engine to read the value of EAX
   print('Password is %d.' % ql.uc.reg_read(UC_X86_REG_EAX))

# Setup Qiling engine to execute Linux ELF with the example x86 Linux rootfs 
# provided with Qiling (in examples/rootfs/arch)
ql = Qiling(['crackme0x02'],'qiling/examples/rootfs/x86_linux')

# Hook 0x08048448 to callback to hook_func
ql.hook_address(hook_func, 0x08048448)

# Start the ELF emulation
ql.run()
```

# References
-[API docs @ github.com/qilingframework/qiling](https://github.com/qilingframework/qiling/blob/master/docs/API.md) - Initialization options for the Qiling Engine

