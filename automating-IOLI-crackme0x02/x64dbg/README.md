# Introduction

[x64dbg](https://x64dbg.com) is a Windows user-mode debugger that supports scripting natively. The commands in the script are identical to those entered into the commandline textbox at the bottom of x64dbg's window. 

There is also a plugin [x64dbgpy](https://github.com/x64dbg/x64dbgpy) that allows scripts to be written in Python but we won't be covering it here.

# Usage
Scripts are loaded and run in the *Script* tab. 

The example scripts show two ways of scripting the debugger. 

In *x64dbg_with_exe.txt* below, the binary is loaded into the debugger by the script. 

As x64dbg command used to automate the UI, a message box is used to prompt the user to switch between tabs as the `rtu` command (equivalent to *Debug > Run to user code*) switches the active tab to the CPU tab where the disassembly is shown.

```
initdbg "crackme0x02.exe" // this must be set to the absolute path to the crackme binary

// The following lines are needed as the GUI switches from Script tab to CPU tab after the initdbg 
msg "Return to Script tab and press Space to continue running script"
pause
rtu // Run to user code so that we can set the breakpoint in the crackme process

// Continue scripting the rest of the commands
...
```

Alternatively, we can assume that the script user is already at the process entrypoint when starting the script and just enter the debugging commands into the script. This is the approach used in *x64dbg_without_exe.txt* and is more useful for cases like writing a more generic script to process similiar samples of a malware family.

Some common x64dbg commands are shown below.

```
// Log a message which can be viewed in the Log tab.
log "Start of debugging session"

// Set single shot breakpoint at 0x00401382 
bpx "0x00401382", "Set a single shot breakpoint @ 0x00401382", "ss"

// Continue execution
go

// Convert EAX to an signed integer and display to user in a messagebox. 
// The curly braces are used for string formatting
msg "password: {d:eax}"

// Terminate the process
stop
```

# References
1. [Full command reference @ help.x64dbg.com](https://help.x64dbg.com/en/latest/commands/index.html) - Official reference for x64dbg commands
2. [Scripting command reference @ help.x64dbg.com](https://help.x64dbg.com/en/latest/commands/script/index.html) - Additional commands for use in scripts only
3. [Expression function reference @ help.x64dbg.com](https://help.x64dbg.com/en/latest/introduction/Expression-functions.html) - Reference for reading information from GUI or analysis
4. [String formatting reference @ help.x64dbg.com](https://help.x64dbg.com/en/latest/introduction/Formatting.html) - Reference for formatting strings for printing
