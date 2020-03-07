from z3 import *

# Assume a contrived scenario where we are missing the initial value of 
# var_c  but we do know the final value of eax and that var_c is greater
# than 0

# Create a z3 solver instance
s = Solver()

# Create memory locations and registers as 32 bit BitVectors
var_8, var_c, eax, edx = BitVecs('var_8 var_c eax edx', 32)

# Commented out var_c initialization as part of scenario. The rest of 
# the instructions are the same as z3-solve.py
var_8 = 0x5A		# mov dword [var_8h], 0x5a
# var_c = 0x1EC		# mov dword [var_ch], 0x1ec
edx = var_c			# mov edx, dword [var_ch]
var_8 += edx		# lea eax, [var_8h] and # add dword [eax], edx
eax = var_8			# mov eax, dword [var_8h]
eax = eax * var_8	# imul eax, dword [var_8h]


# Add constraints to the solver to define the limits or values of the 
# BitVecs should obey
s.add(eax == 0x52B24)
s.add(var_c > 0)

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
