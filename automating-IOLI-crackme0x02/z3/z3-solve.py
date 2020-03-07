from z3 import *

# Create memory locations and registers as 32 bit BitVecs. BitVecs in Z3
# support xor unlike Ints. We don't use xor here but it's good to know.
var_8, var_c, eax, edx = BitVecs('var_8 var_c eax edx', 32)
 
# Convert the x86 instructions to Python
var_8 = 0x5A		# mov dword [var_8h], 0x5a
var_c = 0x1EC		# mov dword [var_ch], 0x1ec
edx = var_c			# mov edx, dword [var_ch]
var_8 += edx		# lea eax, [var_8h] and # add dword [eax], edx
eax = var_8			# mov eax, dword [var_8h]
eax = eax * var_8	# imul eax, dword [var_8h]

print("Password is " + str(eax))
