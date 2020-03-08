import frida
import sys

# Create and suspend process
pid = frida.spawn('crackme0x02')

# Create a Frida session and attach to our process
session = frida.attach(pid)

# Create JavaScript to be injected into our process
script = session.create_script("""
// Hook address instead of function
Interceptor.attach(ptr('0x8048448'), {
	onEnter: function(args) {
		// Prints context as JSON, useful for debugging purposes
		//console.log(JSON.stringify(this.context));
	
		// Read value of EAX from thread context
		var password = this.context.eax.toInt32();
    
		// Send password to Python message handler
		send('Correct password is ' + password);
		send('Press Ctrl+D to detach from process');
	},
});


// Hook main function which starts at 0x80483e4
Interceptor.attach(ptr('0x80483e4'), {
	onEnter: function(args) {
		// For some reason. args don't contain any values.
	
		// Based on disassembly in Radare2, function prototype of main 
		// is int main (int argc, char **argv, char **envp);
	
		// To get first value of char **argv (the binary name), we'll 
		// need the second argument passed to main() at esp+8 and 
		// dereference it twice
		send('Binary name is ' + ptr(this.context.esp).add(8).readPointer().readPointer().readUtf8String());
	
		// This is for demonstrating passing of values between onEnter 
		// and onLeave callbacks
		this.functionName = 'main()';
	},
	onLeave: function(retval) {
		console.log('Exiting ' + this.functionName);
	}
});
""")

def on_message(message, data):
	# Print informational messages
	if message['type'] == 'send': 
		print('\n[i] %s' % message['payload'])
	# Get notified of errors in our JavaScript
	elif message['type'] == 'error':
		print('\n[!] %s' % message['stack'])

# Setup handler to process messages from JavaScript injected into process
script.on('message', on_message)

# Load our JavaScript into our process
script.load()

# Resume the process
frida.resume(pid)

# Keep Frida session alive until we detach it from the process
sys.stdin.read()

# Detach Frida session from process
session.detach()
