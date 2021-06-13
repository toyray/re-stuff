#!/usr/bin/env ruby

require 'metasm'
include Metasm

=begin
# Original disassembly @ 0x804842B exported from IDA
# Probably doing something wrong, but add [eax], edx doesn't write back to
# [ebp+var_8], so cheated and used ecx as scratch register
mov     [ebp+var_8], 5Ah ; 'Z'
mov     [ebp+var_C], 1ECh
mov     edx, [ebp+var_C]
lea     eax, [ebp+var_8]
add     [eax], edx
mov     eax, [ebp+var_8]
imul    eax, [ebp+var_8]
mov     [ebp+var_C], eax
mov     eax, [ebp+var_4]
cmp     eax, [ebp+var_C]
=end
#
# Same as code_bind.rb but we remove the assignment to the two local variables
# so that we can inject the context and solve for them
sc = Shellcode.assemble(Ia32.new, <<EOS)
mov     edx, [ebp-0x0c]
lea     eax, dword ptr [ebp-0x08]
mov     ecx, [eax]
add     ecx, edx
mov     [ebp-0x08], ecx
mov     eax, [ebp-0x08]
imul    eax, [ebp-0x08]
mov     [ebp-0x0c], eax
mov     eax, [ebp-0x04]
cmp     eax, [ebp-0x0c]
nop
EOS

handler = sc.encode_string
dasm = sc.init_disassembler

puts "[+] Disassembly\n\n"
dasm.disassemble(0)
bb = dasm.di_at(0).block
puts bb.list

puts "\n[+] Code binding\n\n"
binding = dasm.code_binding(bb.list.first.address, bb.list.last.address)
binding.each{|key, value|
  puts "-> #{Expression[key]} => #{Expression[value]}"
}

puts "\n[+] Symbolic binding\n\n"

# Map names to local stack variables so that semantics are easier to understand
symbolism = {
    Indirection[[:ebp, :+, -4], 4, nil] => :var_input,
    Indirection[[:ebp, :+, -8], 4, nil] => :var_temp,
    Indirection[[:ebp, :+, -0xc], 4, nil] => :var_flag,
}

def inject(binding, symbolism)
    return binding if not symbolism or symbolism.empty?
    new_binding = {}
    binding.each{|k, val|
        k = Expression[k].bind(symbolism)
        val = Expression[val].bind(symbolism)
        new_binding[Expression[k].reduce_rec] = Expression[val].reduce_rec
    }
    new_binding
end

symbolic_binding = inject(binding, symbolism)
symbolic_binding.each{|key, value|
  puts "-> #{Expression[key]} => #{Expression[value]}"
}

puts "\n[+] Symbolic execution\n\n"

# Create a context and assign values to local variables
context = {
  :var_temp => 0x5a,
  :var_flag => 0x1ec,
}

def sym_exec(binding, context)
    binding_update = {}
    binding.each{|key, val|
        val = Expression[Expression[val].bind(context)].reduce_rec
        binding_update[key] = val
    }

    # update context, with solved binding
    context.update(binding_update)
end

sym_exec(symbolic_binding, context)
context.each{|key, value|
  puts "-> #{Expression[key]} => #{Expression[value]}"
}

puts "\n[+] Flag is #{context[:var_flag].to_s(10)}"
