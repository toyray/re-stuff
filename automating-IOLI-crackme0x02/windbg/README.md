# Introduction

The official Microsoft Windows debugger **WinDbg** offers two ways to script your debugging sessions.

1. Debugger command programs
2. JavaScript debugger scripts

There are also NatVis scripts that are used for visualization instead of automating debugging tasks (not covered here).


# Usage

## Debugger command programs
Debugger command programs are essentially sequences of WinDbg commands and can be executed at the WinDbg command line with `$$< path\to\classic.txt`. Control flow tokens such as `.if` and `.while` are supported.

Excerpt from  *classic.txt*
```
$$ Create a one-shot breakpoint and print password
$$ .if is a contrived example of control flow token usage
bp /1 00401382 ".if (eax>0) { .printf \"Password is %d.\n\n\",eax }"
``` 

## JavaScript debugger scripts
JavaScript Debugger scripts are supported by the newer versions of WinDbg and WinDbg Preview (available as a free download from the Windows Store but for Windows 10 OSes only). Windows 10 trial VMs can be downloaded from [Microsoft Edge Developers Center](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/).

I recommend using WiinDbg Preview for script development as it provides convenient features such as a scripting window (with Intellisense auto-complete!) and automatic reloading and execution when you save changes to your scripts.

To run JavaScript scripts, *jsprovider.dll* needs to be loaded (this is the default in WinDbg Preview, so you can omit this step). Check that JavaScript provider is loaded via `.scriptproviders`

```
.load jsprovider.dll (by default)
.scriptproviders

Available Script Providers:
    NatVis (extension '.NatVis')
    JavaScript (extension '.js')

```

Execute your script. With `.scriptload`, only `initializeScript()` function will be called, with `.scriptrun`, both `initializeScript()` and `invokeScript()` will be called.

```
.scriptload path\to\callbacks.js
.scriptrun path\to\basic.js
```

The example *.js* scripts are as follows:
- *basic.js* is the JavaScript equivalent of the commands in *classic.txt*
- *callback.js* demonstrates how to use Javascript functions as breakpoint commands (adapting code from doar-e's excellent reference) and to define debugger extensions that can be invoked with the `!command` syntax in the WinDbg commandline.

Some Javascript code from *basic.js* below.

```javascript
host.diagnostics.debugLog("Printing message to console \n");

let cp = host.currentProcess;
let ctrl = host.namespace.Debugger.Utility.Control;
	
// Set the breakpoint if not set
// Find any breakpoints with our address with a LINQ query
let breakpointsAlreadySet = cp.Debug.Breakpoints.Any(c => c.Address == '0x401382');
if (!breakpointsAlreadySet) {
  let bp = ctrl.SetBreakpointAtOffset('0x401382', '0');
  // Set a command to execute when the breakpoint is hit
  bp.Command = '.if (eax>0) { .printf "***> Password is %d.\n\n",eax }';
}
```

Official documentation on JavaScript debugger scripts is rather sparse e.g. setting of breakpoints. doar-e's materials were extremely helpful to fill the gaps, see the references sections for others.

A handy way to discover function definitions for the JavaScript objects (the ones starting with *host*) is via `dx` and clicking through the displayed DML links. For example, `dx -r1 @$debuggerRootNamespace.Debugger.Utility.Control` displays the four function definitions for the Control object.

# References
- [Debugger command programs @ docs.microsoft,com](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/elements-of-a-debugger-command-program)
- [JavaScript debugger scripting @ doc.microsoft.com](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/javascript-debugger-scripting)
- [Debugger data model, JavaScript reference @ doar-e.github.io](https://doar-e.github.io/blog/2017/12/01/debugger-data-model/) - Most detailed non-official doc on JavaScript debugger scripting, Debugger data model and some bits on Time Travel Debugging
- [JavaScript debugger scripting cheatsheet @ github.com/hugsy/defcon_27_windbg_workshop](https://github.com/hugsy/defcon_27_windbg_workshop/blob/master/windbg_cheatsheet.md#windbg-javascript-reference)
- [JavaScript debugger scripting intro @ blog.talosintelligence.com](https://blog.talosintelligence.com/2019/02/windbg-malware-analysis-with-javascript.html) - another handy reference on Javascript debugger scripting
- [Debugging your debugger scripts in WinDbg @ blogs.msdn.microsoft.com](https://blogs.msdn.microsoft.com/windbg/2017/06/30/script-debugging-walkthrough/)
