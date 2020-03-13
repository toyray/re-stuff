// Run this script with the following commands
// WinDbg:
// .load jsprovider.dll
// .scriptrun path\to\basic.js

// WinDbg Preview
// Use Scripting > Open Script ... and Execute

// initializeScript always called on load via .scriptload, .scriptrun
function initializeScript()
{
    host.diagnostics.debugLog("***> initializeScript called \n");
}

// invokeScript always called with .scriptrun. Not called when script loaded via .scriptload
function invokeScript()
{
    let cp = host.currentProcess;
    let ctrl = host.namespace.Debugger.Utility.Control;
	
	// Set the breakpoint if not set
    let breakpointsAlreadySet = cp.Debug.Breakpoints.Any(c => c.Address == '0x401382');
    if (!breakpointsAlreadySet) {
        let bp = ctrl.SetBreakpointAtOffset('0x401382', '0');
        bp.Command = '.if (eax>0) { .printf "***> Password is %d.\n\n",eax }';
		
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