# Introduction

[Z3](https://github.com/Z3Prover/z3) is a theorem prover from Microsoft Research. It's useful for determining combinations of values that are valid for a set of arithmetic or logical operations or to simplify those operations.

While Z3 uses SMT-LIB commands by default, the example scripts are written in Python because for RE work, it's useful to integrate the results of our z3 code with other Python code.

To use z3 with Python, install `pip install z3-solver` which will install z3 and the necessary Python files. `import * from z3` and you are ready to go!

# Usage

The first script *z3-solve.py* is similar to emulation of the same x86 code since the initial values of *var_8h* and *var_ch* are known. In such cases, emulation using other tools such as [Radare2](../r2emu) or [Unicorn](../unicorn) is preferable. This still has its uses when dealing with dynamically injected code in interpreted languages Python for example.

Use **BitVec** to represent registers and memory locations as they can work with xor operations unlike **Int**. When you print a BitVec, it will either display a value or a formula if that BitVec depends on another BitVec that doesn't have a solvable value at that point in time.

```python
# Create memory locations and registers as 32 bit BitVecs. BitVecs in Z3
# support xor unlike Ints. We don't use xor here but it's good to know.
var_8, var_c, eax, edx = BitVecs('var_8 var_c eax edx', 32)

# Convert the x86 instructions to Python
var_8 = 0x5A		# mov dword [var_8h], 0x5a
var_c = 0x1EC		# mov dword [var_ch], 0x1ec
...
```

The second script *z3-solve-miss-1-var.py* assumes a scenario where the initial value of *var_ch* is unknown but the final value of EAX is known. This is usually the most common use case during RE sessions where we know the algorithm and the final result but the initial values of one or more variables are unknown.

For z3 to solve anything, a Solver instance is required. Add constraints with the `add()` methods. Multiple constraints are ANDed by default, other logical operators like OR are supported.

Use the `check()` method to determine if there is a solution. If there is, *check()* will return `sat` and the possible values for the solution can be displayed with the  `model()` method. Note that there may be more than one solution, so to limit the number of possible solutions, apply as many constraints as possible.

```python
# Create a z3 solver instance
s = Solver()

# Operate on your BitVecs here (similar to first script)
...

# Add constraints to the solver to define the limits or values of the
# BitVecs should obey
s.add(eax == 0x52B24)

# Check for satisfiability and print values in model
if s.check() == sat:
	# This should print [var_c = 492] which is 0x1EC
	print(s.model())

	# Alternatively use the identifier specified in the BitVec call to
	# get a particular value. The BitVecNumRef value can be casted to
	# long, signed_long, string as follows
	print "var_c is " + hex(s.model()[var_c].as_long())
else:
	print "unsat"
```

The third script *z3-simplify.py* assumes another scenario where the algorithm is known but we want to simplify the algorithm for easier understanding. This is especially useful for binaries with junk code interpersed with the actual code.

This script is almost similar to the first script except that the initialization code for *var_8h* and *var_ch* are removed and the BitVec for eax is printed which should display `(var_8 + var_c)*(var_8 + var_c)` which is the algorithm to calculate the password.

# References
1. [z3 tutorial @ github.com/ericpony/z3py-tutorial](https://github.com/ericpony/z3py-tutorial) - Good set of tutorials that cover both basic and advanced features of z3
2. [Intro to binary analysis with z3 and Angr @ F-Secure labs](https://labs.f-secure.com/archive/intro-to-binary-analysis-with-z3-and-angr/) - Good set of slides on basics of z3
3. [Basic barebones script @ github.com/Overcl0k/z3-playground](https://github.com/0vercl0k/z3-playground/blob/master/essentials/hello-world.py) - Hello World for z3
4. [z3 simplification @ 0xeb.net](https://0xeb.net/2018/03/using-z3-with-ida-to-simplify-arithmetic-operations-in-functions/) - Using z3 to simplify complicated ASM
