from winappdbg import Debug, EventHandler

# EventHandler class is required to handle all debugging events
class eventHandler(EventHandler):
	
	# create_process and load_dll are predefined names for notification
	# functions to handle process creation and dll loading events
	
	# More info at https://winappdbg.readthedocs.io/en/latest/Debugging.html#the-eventhandler-class
	def create_process(self, event):
	
		# Breakpoint at 0x00401382 in crackme0x02.exe
		pid = event.get_pid()
		event.debug.break_at(pid, 0x401382, breakpoint_401382_callback)
		
	def load_dll(self, event):
		
		# HACK: Unable to find a way to send STDIN for the password
		# entry, so setting a breakpoint at scanf() to immediately
		# return to callee. This is not actually needed since 
		# WinAppDbg seems to continue on without any input
		
		# Get DLL module currently being loaded
		module = event.get_module()
		if module.match_name("msvcrt.dll"):
			pid = event.get_pid()
			
			# Resolve starting address of scanf() function
			address = module.resolve("scanf")

			event.debug.break_at( pid, address, breakpoint_scanf_callback )
	
# Callback for breakpoint 401382 gets thread context for the value of 
# EAX which has the password
def breakpoint_401382_callback(event):
	thread = event.get_thread()
	context = thread.get_context()
	print "Password is", context['Eax']
	
	# Stop debugging
	event.debug.stop()

# Callback for scanf 
def breakpoint_scanf_callback(event):
	process = event.get_process()
	thread = event.get_thread()
	context = thread.get_context()	
	
	# Get the address of the top of the stack, at the start of the function,
	# this contains the return address
	stack = thread.get_sp()
	
	# Read the return address from the stack
	address = process.read_pointer(stack)
	
	# Fix the stack as scanf is a cdecl function with two parameters
	context["Esp"] += 0x10
	
	# Update the thread context
	thread.set_context(context)
	
	# Set the EIP to the saved return address
	thread.set_pc(address)

# Create a Debug object with our eventHandler and use a with context to 
# automatically cleanup the object once debugging has stopped
with Debug(eventHandler(), bKillOnExit = True ) as dbg:
	dbg.execl('crackme0x02.exe')
	dbg.loop()