from z3 import *

# Assume a contrived scenario where we are missing both initial values 
# of var_8 and var_c. 

# Even if we know the final value of eax, without additional constraints
# we are unlikely to find the correct combination of values for var_8 
# and var_c.

# Instead we can simplify the formula that is used to calculate the 
# password in eax, which in some cases is good enough

# Create memory locations and registers as 32 bit BitVectors
var_8, var_c, eax, edx = BitVecs('var_8 var_c eax edx', 32)

# Commented out var_8 and var_c initialization as part of scenario. The 
# rest of the instructions are the same as z3-solve.py

# var_8 = 0x5A		# mov dword [var_8h], 0x5a
# var_c = 0x1EC		# mov dword [var_ch], 0x1ec
edx = var_c			# mov edx, dword [var_ch]
var_8 += edx		# lea eax, [var_8h] and # add dword [eax], edx
eax = var_8			# mov eax, dword [var_8h]
eax = eax * var_8	# imul eax, dword [var_8h]

# We don't really need simplify here as printing eax will show the 
# formula which should be "(var_8 + var_c)*(var_8 + var_c)"
print simplify(eax)
