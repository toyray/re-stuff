// Run this script with the following commands

// WinDbg:
// .load jsprovider.dll
// .scriptload path\to\callback.js
// !solve

// WinDbg Preview
// Use Scripting > Open Script ... and Execute
// !solve

// initializeScript always called on load via .scriptload, .scriptrun
function initializeScript()
{
    host.diagnostics.debugLog("***> initializeScript called \n");
	
	// Function alias are good for defining extension functions for generic use cases
	// We define the solve extension here to call __solveCrackme when !solve is entered as a WinDbg command
	return [new host.functionAlias(__solveCrackme, "solve")];
}

// solveCrackme is no way generic, done just as an example
function __solveCrackme()
{
    let cp = host.currentProcess;
    let ctrl = host.namespace.Debugger.Utility.Control;
	
	// Set the breakpoint if not set
    let breakpointsAlreadySet = cp.Debug.Breakpoints.Any(c => c.Address == '0x401382');
    if (!breakpointsAlreadySet) {
        let bp = ctrl.SetBreakpointAtOffset('0x401382', '0');
		// A way to use a JavaScript callback to handle a breakpoint. Adapted from 
		// https://doar-e.github.io/blog/2017/12/01/debugger-data-model/#setting-breakpoints
        bp.Command = 'dx @$scriptContents.handle_bp(); gc';
		
		// Print breakpoints
        for (let bp of ctrl.ExecuteCommand("bl")) {
            host.diagnostics.debugLog(bp + "\n");
        }
    } else {
		 host.diagnostics.debugLog("***> Breakpoints already set\n");
    }
    
    host.diagnostics.debugLog("***> Enter gc to continue\n");
	// Executing gc doesn't work, so ask user to continue manually
    //ctrl.ExecuteCommand("gc");
}

// Callback to handle breakpoint
function handle_bp()
{
	let regs = host.currentThread.Registers.User;
	host.diagnostics.debugLog("***> Password is " + regs.eax + "\n");
}