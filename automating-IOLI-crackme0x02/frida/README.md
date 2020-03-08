# Introduction

[Frida](https://frida.re/) is a tool for dynamically instrumenting and hooking binaries.

The example code uses Python to control the Frida session in which a JavaScript script containing hooks and callbacks are injected in the Linux binary and triggered as the binary executes.

Frida can hook both functions and individual addresses, but is substantially more powerful when hooking and manipulating functions.

# Usage

Frida can either start a process in suspended state with `spawn()` or directly attach to an already running process with `attach()` depending on the use case.

```python
import frida

# Create and suspend process
pid = frida.spawn('crackme0x02')

# Create a Frida session and attach to our process
session = frida.attach(pid)
```

Load the JavaScript code from a file or include it inline as in the example below. For longer scripts, debugging will be easier if the JavaScript is in a separate script so that the line numbers reported by Frida are accurate.
```javascript
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
""")
```

To pass messages from JavaScript to Python, use `send()` in the JavaScript code and set up a message handler to process those messages.

```python
def on_message(message, data):
	# Print informational messages
	if message['type'] == 'send': 
		print('\n[i] %s' % message['payload'])
	# Get notified of errors in our JavaScript
	elif message['type'] == 'error':
		print('\n[!] %s' % message['stack'])

# Setup handler to process messages from JavaScript injected into process
script.on('message', on_message)
```

Once everything is setup, load the script, resume the process if needed and let the script do its thing!

```python
# Load our JavaScript into our process
script.load()

# Resume the process (if process was created in suspended state)
frida.resume(pid)
```

The line below is required as sometimes commandline binaries exit before the callbacks finish processing. 

```python
# Keep Frida session alive
import sys
sys.stdin.read()
```

Detach the Frida session when we're done.
```python
session.detach()
```

# References
1. [Official docs @ frida.re](https://frida.re/docs/home/) - Go through the Functions and Messages tutorials to get up to speed
2. [JavaScript API reference @ frida.re](https://frida.re/docs/javascript-api/) - Handy reference when writing more complicated scripts
