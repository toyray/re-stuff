# Introduction

[WinAppDbg](https://github.com/MarioVilas/winappdbg) is a powerful tool for instrumenting and debugging Windows binaries programmatically in Python.

Note that 32-bit and 64-bit Python 2.7.x are required to debug 32-bit and 64-bit Windows binaries respectively, so remember to install and execute your script with the correct bitness of Python. Installation can be done by running `install.bat` or `python setup.py install` from the root folder of the WinAppDbg source code.

As the crackme binary is 32-bit, execute the example script (written for WinAppDbg 1.6) with 32-bit Python 2.7.x.

Scripting in WinAppDbg uses an event-driven approach instead of the linear approach when scripting other debuggers.

# Usage

Create a `Debug` object with an `EventHandler` object and user-defined callback functions to handle and process debugging event notifications e.g. breakpoints, hooks, etc. The official documentation on Debugging (referenced below) is essential reading for quickly getting up to speed.

An excerpt of the example script is shown below.

```python
from winappdbg import Debug, EventHandler

# EventHandler class is required to handle all debugging events
class eventHandler(EventHandler):
	
	# create_process is a predefined name for notification function
	# to handle process creation and dll loading events
	
	# More info at https://winappdbg.readthedocs.io/en/latest/Debugging.html#the-eventhandler-class
	def create_process(self, event):
	
		# Breakpoint at 0x00401382 in crackme0x02.exe
		pid = event.get_pid()
		event.debug.break_at(pid, 0x401382, breakpoint_401382_callback)
		
	
# Callback for breakpoint 401382 gets thread context for the value of 
# EAX which has the password
def breakpoint_401382_callback(event):
	thread = event.get_thread()
	context = thread.get_context()
	print "Password is", context['Eax']
	
	# Stop debugging
	event.debug.stop()

# Create a Debug object with our eventHandler and use a with context to 
# automatically cleanup the object once debugging has stopped
with Debug(eventHandler(), bKillOnExit = True ) as dbg:
	dbg.execl('crackme0x02.exe')
	dbg.loop()
```

# References
1. [Debugging docs @ winappdbg.readthedocs.io](https://winappdbg.readthedocs.io/en/latest/Debugging.html) - Official documentation on developing Debugging code with WinAppDbg
2. [Programming Guide @ winappdbg.readthedocs.io](https://winappdbg.readthedocs.io/en/latest/ProgrammingGuide.html) - More examples on what can be developed with WinAppDbg
3. [Example code @ github.com/MarioVilas/winappdbg](https://github.com/MarioVilas/winappdbg/tree/master/examples) - Official code examples
4. [WinAppDbg hooking examples @ parisya.net](https://parsiya.net/categories/winappdbg/) - Good examples on using WinAppDbg for hooking 
