# Introduction

GDB debugging sessions can be automated via command files. 

The example script is very simple as my older version of GDB (7.7.1) doesn't support piping output of GDB commands to external programs, but users of GDB can use the new `pipe` command to perform additional processing :grin:

# Usage

A command file is a text file containing a sequence of gdb commands. `#` are used for defining comments and empty lines are ignored.

Command files can be executed in two ways:
1. Starting gdb with the `--command` argument and specifying a path to the command file
2. Starting a gdb debugging session and then running the `source` command with the path to the command file at the prompt

# References
- [Command cheatsheet by fristle](https://cheatography.com/fristle/cheat-sheets/closed-source-debugging-with-gdb/) - reference of usual commmands when debugging with GDB
- [Command files @ sourceware.org](https://sourceware.org/gdb/onlinedocs/gdb/Command-Files.html) - documentation on command files
- [pipe GDB command @ sourceware.org](https://sourceware.org/gdb/current/onlinedocs/gdb/Shell-Commands.html#Shell-Commands) - documentation on the `pipe` command in GDB
