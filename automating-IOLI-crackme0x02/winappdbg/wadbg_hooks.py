from winappdbg import Debug, EventHandler, HexDump
from winappdbg.win32 import *

# EventHandler class is required to handle all debugging events
class eventHandler(EventHandler):
	
	# create_process and load_dll are predefined names for notification
	# functions to handle process creation and dll loading events
	
	# More info at https://winappdbg.readthedocs.io/en/latest/Debugging.html#the-eventhandler-class
	def create_process(self, event):
	
		# Breakpoint at 0x00401382 in crackme0x02.exe
		pid = event.get_pid()
		event.debug.break_at(pid, 0x401382, breakpoint_401382_callback)

	# Define the APIs that we want to hook
	# We only define the mandatory parameter for scanf here
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