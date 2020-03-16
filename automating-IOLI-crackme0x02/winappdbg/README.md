# Introduction

[WinAppDbg](https://github.com/MarioVilas/winappdbg) is a powerful tool for instrumenting and debugging Windows binaries programmatically in Python.

Note that 32-bit and 64-bit Python 2.7.x are required to debug 32-bit and 64-bit Windows binaries respectively, so remember to install and execute your script with the correct bitness of Python. Installation can be done by running `install.bat` or `python setup.py install` from the root folder of the WinAppDbg source code.

As the crackme binary is 32-bit, execute the example script (written for WinAppDbg 1.6) with 32-bit Python 2.7.x.

Scripting in WinAppDbg uses an event-driven approach instead of the linear approach when scripting other debuggers.

# Usage

Create a `Debug` object with an `EventHandler` object and user-defined callback functions to handle and process debugging event notifications e.g. breakpoints, hooks, etc. The official documentation on Debugging (referenced below) is essential reading for quickly getting up to speed.

An excerpt from *wadbg.py* is shown below.

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

*wadbg_hooks.py* demonstrates the use of API hooks which are handy for intercepting calls to Win32 APIs. The official docs has another example [here](https://winappdbg.readthedocs.io/en/latest/Debugging.html#example-9-intercepting-api-calls).

To use this feature, define the hooks using the `api_hooks` variable and write your *pre_* and *post_* function callbacks within the EventHandler class. 

```python
# Define the APIs that we want to hook
# scanf allows multiple optional arguments but We only define the mandatory 
# parameter for scanf here. We still can access the optional arguments within
# our callback
apiHooks = {
	 'msvcrt.dll' : [
		( 'scanf', (PVOID, DWORD) )
	]
}
		
# Callback when leaving scanf
def post_scanf(self, event, retval):
	print 'Return value from scanf is %s' % HexDump.integer(retval)

# Callback when entering scanf 
# We define *args as an argument list with the splat operator as 
# scanf can have multiple optional arguments depending on the
# first format string argument
def pre_scanf(self, event, return_address, format_string, *args):
	# As this callback would be called for all calls to scanf, we
	# check the return address to confirm that this is the call we
	# care about
	if (return_address == 0x00401365):
		print 'Format string at address %s is "%s"' % (\
		HexDump.address(format_string), \
		event.get_process().peek_string(format_string))
		
		# args contain pointers to one or more buffers to store
		# the values inputted by user
		if (len(args) > 0):
			print 'Buffer for user input at address: %s' % HexDump.address(args[0])
			event.get_process().write_uint(args[0], 338724)
```

# References
1. [Debugging docs @ winappdbg.readthedocs.io](https://winappdbg.readthedocs.io/en/latest/Debugging.html) - Official documentation on developing Debugging code with WinAppDbg
2. [Programming Guide @ winappdbg.readthedocs.io](https://winappdbg.readthedocs.io/en/latest/ProgrammingGuide.html) - More examples on what can be developed with WinAppDbg
3. [Example code @ github.com/MarioVilas/winappdbg](https://github.com/MarioVilas/winappdbg/tree/master/examples) - Official code examples
4. [WinAppDbg hooking examples @ parisya.net](https://parsiya.net/categories/winappdbg/) - Good examples on using WinAppDbg for hooking 
