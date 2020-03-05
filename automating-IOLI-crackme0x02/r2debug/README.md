# Introduction

r2pipe can be used to script the same commmands used in Radare2's interactive shell.

# Usage

Create a r2pipe instance for a file *binary* using `open()`.

```
r2 = r2pipe.open('binary')
```

If the script requires debugging commands, create a r2pipe instance with debugging enabled.

```
r2 = r2pipe.open('binary', flags=['-d'])
```

If the binary requires stdin, a *rarun2* debug profile is required. An example profile for this crackme can be seen [here](/crackme0x02.rr2)

```
r2 = r2pipe.open('binary')
r2.cmd('e dbg.profile=profile.rr2')
r2.cmd('ood') # Reload the binary to use the rarun2 profile
```

Commands for radare2 are executed using `cmd()`

```
r2.cmd('pdf')
```

Once you're done with the r2pipe instance, close it with `quit()`

```
r2.quit()
```

# References
* [r2pipe @r2wiki](https://r2wiki.readthedocs.io/en/latest/home/radare2-python-scripting/) - Installation and usage instructions for r2pipe
* [r2pipe @ radare2 book](https://radare.gitbooks.io/radare2book/content/scripting/r2pipe.html) - Example code for the different language bindings
* [rarun2 @ radare2 book](https://radare.gitbooks.io/radare2book/content/tools/rarun2/intro.html) - Configuration for rarun2 profiles
