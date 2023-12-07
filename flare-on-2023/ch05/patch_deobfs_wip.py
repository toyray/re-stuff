import os
import shutil

from capstone import *
from capstone.x86 import *

from keystone import *

from unicorn import *
from unicorn.x86_const import *

class Disasm:

    def __init__(self, cfg):
        self.disasm_size = cfg.get("disasm_size", 50)
        self.block_max_insn = cfg.get("max_insn", 9000)
        self.patch_ext = cfg.get("patch_ext", ".patched")
        self.max_func_size = cfg.get("max_func_size", 0xb000)
        self.max_funcs = cfg.get("max_funcs", 150)

    def load(self, filename):
        self.filename = filename
        self.new_filename = filename + self.patch_ext
        new_code_start = self.copy_and_extend_file(self.filename, self.new_filename)

        self.f = open(self.filename, "rb")
        self.new_code_start = new_code_start
        self.new_code_index = 0
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

        self.patch_cond_jumps = {}

    def copy_and_extend_file(self, src, dest):
        """
        Extend shellcode blob to fit in reconstructed code
        """
        size = os.path.getsize(src)
        round_size = ((size // 0x1000) + 1) * 0x1000
        total_size = round_size + self.max_func_size * self.max_funcs
        shutil.copyfile(src, dest)
        with open(dest, "ab") as f:
            f.write(b"\x00" * (total_size - size))
        return round_size

    def wipe_existing_code(self):
        """
        Wipes existing code to remove all those annoying code references due to
        the old obfuscated jump funcs
        """
        with open(self.new_filename, "rb+") as f:
            f.write(b"\xc3" * self.new_code_start)

    def cleanup(self):
        if self.f is not None:
            self.f.close()

    def read_va(self, va, size=-1):
        """
        Read bytes of specified size starting from virtual address from file

        Since this is a shellcode blob, raw and virtual addresses are
        identical and there's no translation required
        """
        read_len = size
        if read_len == -1:
            read_len == self.disasm_size

        self.f.seek(va)
        data = self.f.read(read_len)
        return data

    def get_codes(self, va, size=-1):
        """
        Disassemble bytes starting from virtual address
        """
        data = self.read_va(va)
        return self.md.disasm(data, va)

    def patch_bytes(self, va, code_bytes):
        """
        Patch raw bytes into new file
        """
        with open(self.new_filename, "rb+") as f:
            f.seek(va)
            f.write(code_bytes)

    def patch_code_info(self, code_info):
        """
        Combine code bytes and patch into file
        """
        if len(code_info) == 0:
            return

        va = code_info[0]["addr"]

        code_bytes = b""
        for ci in code_info:
            code_bytes += bytes(ci["bytes"])

        with open(self.new_filename, "rb+") as f:
            f.seek(va)
            f.write(code_bytes)

    def gen_flow_offset_bytes(self, src, dest, insn_size):
        """
        Generate bytes for calls and jumps
        """
        # Ensure that offset is signed
        offset = dest - src - insn_size
        offset_bytes = int.to_bytes(offset, length=4,
            byteorder="little", signed=True)
        return offset_bytes

    def get_patch_force_jump_bytes(self, src, dest):
        """
        Generate instruction bytes for jumps to end unrolled loops
        """
        flow_bytes = self.gen_flow_offset_bytes(src, dest, 5)
        new_code_bytes = b"\xe9" + flow_bytes
        return new_code_bytes

    def get_patch_cond_jump_bytes(self, insn_bytes, src, dest):
        """
        Generate instruction bytes for new destination of conditional jumps
        """
        # Working with bytes and not Capstone instructions here
        flow_bytes = self.gen_flow_offset_bytes(src, dest, len(insn_bytes))
        new_code_bytes = insn_bytes[0:2] + flow_bytes
        return new_code_bytes

    def handle_jump(self, insn):
        """
        Get jump destination
        """
        dest = insn.operands[0]
        if dest.type == X86_OP_IMM:
            return dest.imm
        else:
            return None

    def handle_call(self, insn, current_ip):
        """
        Get call destination and instruction bytes
        """
        # Calls are E8, with 1 byte for opcode
        dest = insn.operands[0]
        if dest.type == X86_OP_IMM:
            # Manually point jump to our relocated func
            dest = dest.imm
            src = current_ip

            flow_bytes = self.gen_flow_offset_bytes(src, dest, insn.size)
            new_code_bytes = insn.bytes[0:1] + flow_bytes
            return new_code_bytes, dest
        else:
            return insn.bytes, None

    def handle_lea(self, insn, current_ip):
        """
        Get lea address and instruction bytes
        """
        # LEA should have 3 bytes for opcode
        # Example disassembly from Capstone
        # lea r8, [rip + 0x33edb]
        dest = insn.operands[1]
        if dest.type == X86_OP_MEM and insn.reg_name(dest.mem.base) == "rip":
            offset = dest.mem.disp
            dest = insn.address + offset + insn.size
            src = current_ip

            flow_bytes = self.gen_flow_offset_bytes(src, dest, insn.size)
            new_code_bytes = insn.bytes[0:3] + flow_bytes
            return new_code_bytes, dest
        else:
            return insn.bytes, None

    def handle_conditional_jumps(self, insn, current_ip):
        """
        Get conditional jump destination and instruction bytes
        """
        # Conditional jumps are 0f XX, with 2 byte for opcode
        dest = insn.operands[0]
        if dest.type == X86_OP_IMM:
            dest = dest.imm
            src = current_ip

            flow_bytes = self.gen_flow_offset_bytes(src, dest, insn.size)
            new_code_bytes = insn.bytes[0:2] + flow_bytes
            return new_code_bytes, dest
        else:
            return insn.bytes, None

    def start(self, va, single_func=False):
        """
        Process one or more functions
        """
        new_funcs = {va}
        proc_funcs = set()

        print_disasm = single_func
        while True:
            if len(new_funcs) == 0:
                break

            nva = new_funcs.pop()
            if nva not in proc_funcs:
                # print("Processing 0x%x" % nva)
                proc_funcs.add(nva)

                flows = self.disasm_func(nva, print_disasm)
                # print("Adding new flows: " + ", ".join(hex(f) for f in flows))
                new_funcs.update(flows)
                # print("Remaining funcs: %d" % len(new_funcs))

                # Update code index so that we can position the instruction
                # bytes at the correct place inside the new code section
                self.new_code_index += 1

                if single_func:
                    break
        print("Done, processed %d flows" % self.new_code_index)

    def disasm_func(self, va, print_disasm=True):
        jump_flows = set()
        call_flows = set()

        codes = self.get_codes(va)

        # Create a jump from VA to new code section
        new_ip = self.new_code_start + self.max_func_size * self.new_code_index
        new_va = new_ip

        # Patch the jump bytes first
        new_jump_bytes = self.gen_flow_offset_bytes(va, new_ip, 5)
        self.patch_bytes(va, b"\xe9" + new_jump_bytes)

        # Store the bytes as addresses + instruction bytes so that we can do a
        # second pass and fix the conditional jumps
        code_info = []

        # Store cmp and test instructions for checking unrolled loops
        cmp_blocks = {}

        insn_count = 0
        while True:
            try:
                i = next(codes)
            except StopIteration:
                print("Aborting, no more code")
                break

            insn_count += 1

            if insn_count > self.block_max_insn:
                print("Aborting func disasm for 0x%x, hit block instruction limit" % va)
                break

            # Handle code redirection via jmp
            if i.mnemonic == "jmp":
                next_addr = self.handle_jump(i)

                if next_addr is None:
                    # Not an immediate jump e.g. jmp rax, so we stop the
                    # disassembly
                    if print_disasm:
                        print("0x%x:\t%s\t%s" %(new_ip, i.mnemonic, i.op_str))

                    code_info.append(
                        {
                            "addr": new_ip,
                            "bytes": i.bytes,
                            "inst": i.mnemonic + " " + i.op_str,
                        }
                    )
                    break

                # Jump and ignore the instruction
                codes = self.get_codes(next_addr)
                new_jump = next_addr
                continue

            # Handle infinite loops via cmp and test
            elif i.mnemonic == "cmp" or i.mnemonic == "test":
                if print_disasm:
                    print("0x%x:\t%s\t%s" %(new_ip, i.mnemonic, i.op_str))

                # This is for unrolled loops. Check if we have seen this cmp or
                # test before, if we have, disassemble from this location and try to
                # match code in the same function. If it matches, we patch it to
                # jump to the correct compare and stop the disassembly

                inst = i.mnemonic + " " + i.op_str
                if inst in cmp_blocks.values():
                    addr = self.process_cmp(i.address, code_info)
                    if addr is not None:
                        # We found a match so we will patch the current
                        # instruction with an unconditional jump and end
                        # disassembly of current func
                        jump_bytes = self.get_patch_force_jump_bytes(new_ip, addr)
                        code_info.append(
                            {
                                "addr": new_ip,
                                "bytes": jump_bytes,
                                "inst": "jmp 0x%x" % addr,
                            }
                        )
                        break
                else:
                    cmp_blocks[new_ip] = inst
            else:
                # For all other instructions, print disassembly for manual
                # verification
                if print_disasm:
                    print("0x%x:\t%s\t%s" %(new_ip, i.mnemonic, i.op_str))

            # Patch calls, leas and conditional jumps to point to the correct
            # locations since the code is now located in the new section
            if i.mnemonic == "call":
                # Relocate calls
                call_bytes, dest = self.handle_call(i, new_ip)
                if dest is not None:
                    call_flows.add(dest)
                ins_bytes = call_bytes

            elif i.mnemonic == "lea":
                lea_bytes, dest = self.handle_lea(i, new_ip)
                if dest is not None:
                    call_flows.add(dest)
                ins_bytes = lea_bytes

            elif X86_GRP_BRANCH_RELATIVE in i.groups and X86_GRP_JUMP in i.groups:
                jump_bytes, dest = self.handle_conditional_jumps(i, new_ip)
                if dest is not None:
                    # Patch conditional jumps, if we know that they are supposed to
                    # go elsewhere
                    patch_dest = self.patch_cond_jumps.get(dest, None)
                    if patch_dest is None:
                        jump_flows.add(dest)
                    else:
                        jump_bytes = self.get_patch_cond_jump_bytes(bytes(i.bytes), new_ip, patch_dest)

                ins_bytes = jump_bytes

            else:
                ins_bytes = i.bytes

            # Save the code for fixing conditional jumps and patching the file
            # later
            code_info.append(
                    {
                        "addr": new_ip,
                        "bytes": ins_bytes,
                        "inst": i.mnemonic + " " + i.op_str,
                    }
                )

            # We reach the end of the func, stop disassembly
            if i.mnemonic == "ret":
                break

            # Update the new virtual address so that we can relocate calls correctly
            new_ip += i.size

        # Find duplicate jump destinations that are jumping to another copy of
        # this function
        jump_fixes = self.process_jump_flows(jump_flows, code_info)

        valid_jump_fixes = {}
        for k, v in jump_fixes.items():
            # Add those jumps that we weren't able to find matches to the call
            # flows set to be treated as a unique func
            if v is None:
                call_flows.add(k)
            else:
                # Add valid jump fixes to globals so we can patch directly
                self.patch_cond_jumps[k] = v
                valid_jump_fixes[k] = v

        # Update the jump destinations in the current instruction bytes
        code_info = self.fix_jumps(code_info, valid_jump_fixes)

        # Do another pass to replace register obfuscation
        code_info = self.fix_reg_obfs(code_info)

        # Do another pass to remove nops and generate final code bytes
        patched_bytes, addr_map = self.remove_nops(code_info, new_va)

        # Do another pass with addr_map to point internal jumps to the correct
        # destinations
        patched_bytes = self.fix_internal_jumps(patched_bytes, addr_map, new_va)

        # Write instruction bytes to file
        self.patch_bytes(new_va, patched_bytes)

        return call_flows

    def disasm_block(self, va, size, print_disasm=False):
        """
        Disassemble a block of code sequentially for number of instructions
        specified by size and return a disassembly string
        """
        codes = self.get_codes(va)
        new_ip = va

        block_code = ""

        insn_count = 0
        while True:
            try:
                i = next(codes)
            except StopIteration:
                return block_code

            if insn_count >= size:
                return block_code

            if i.mnemonic == "jmp":
                # Jump and ignore the instruction
                next_addr = self.handle_jump(i)

                if next_addr is None:
                    # Not an immediate jump e.g. jmp rax, stop disassembly
                    if print_disasm:
                        print("0x%x:\t%s\t%s" %(new_ip, i.mnemonic, i.op_str))
                    break

                codes = self.get_codes(next_addr)
                new_jump = next_addr
                continue
            else:
                insn_count += 1

                if print_disasm:
                    print("0x%x:\t%s\t%s" %(new_ip, i.mnemonic, i.op_str))

                if block_code != "":
                    block_code += ";"
                block_code += i.mnemonic + " " + i.op_str

            if i.mnemonic == "ret":
                break

            new_ip += i.size
        return block_code

    def process_jump_flows(self, jump_flows, code_info):
        """
        For each jump destinations, we disasm and try to match it to code in the
        same func

        Return a dict of jump destinations and starting address of matching
        block
        """
        matches = {}
        for j in jump_flows:
            text = self.disasm_block(j, 10)

            addr = self.match_code(text, code_info)
            matches[j] = addr

        return matches

    def process_cmp(self, addr, code_info):
        """
        We disasm cmp and test starting from addr and try to match it to code in
        the same func. This should eliminate unrolled loops

        Return address of match or None
        """
        text = self.disasm_block(addr, 20)
        return self.match_code(text, code_info)

    def match_code(self, text, code_info):
        """
        Simplistic match by instruction disassembly srting

        Returns VA if match or None if no match
        """
        insts = text.split(";")

        if len(insts) == 0:
            return None

        # There may be multiple matches for first instruction, so test all of
        # them
        tested = set()
        current_inst = insts[0]

        while True:
            found = False
            for j, ci in enumerate(code_info):
                if ci["inst"] == current_inst and j not in tested:
                    tested.add(j)
                    found = True
                    break

            # If matching code cannot be found, return
            if not found:
                return None

            matched = True
            for i in range(0, len(insts)):
                # If any instruction don't match, break and try another location
                if i+j >= len(code_info):
                    break

                if insts[i] != code_info[i+j]["inst"]:
                    matched = False
                    break

            if matched:
                return code_info[j]["addr"]

    def fix_jumps(self, code_info, jump_fixes):
        for i, ci in enumerate(code_info):
            # TODO: This is a really shitty way to check for conditional jumps
            # because we are working with string instead of Capstone
            # instructions :(
            if ci["inst"].startswith("j"):
                tokens = ci["inst"].split(" ")
                if len(tokens) != 2:
                    continue

                dest = tokens[1]
                # We only care about jumps to addresses
                if dest.startswith("0x"):
                    new_dest = jump_fixes.get(int(dest, 16), None)
                    if new_dest is not None:
                        jump_bytes = self.get_patch_cond_jump_bytes(
                            bytes(ci["bytes"]), ci["addr"], new_dest)
                        code_info[i]["bytes"] = jump_bytes

        return code_info

## Register obfuscation funcs

    def find_reg_pop(self, code_info, start, reg):
        """
        Look ahead for 10 instructions for a pop
        """
        max_count = start + 11
        if max_count >= len(code_info):
            max_count = len(code_info)

        for i in range(start + 1, max_count):
            ci = code_info[i]
            # If the next instructions contain a push with the same reg, we
            # ignore this as we want the innermost push for thsi reg
            if ci["inst"].startswith("push"):
                tokens = ci["inst"].split(" ")
                if len(tokens) != 2:
                    continue

                dest_reg = tokens[1]
                if dest_reg == reg:
                    return None

            if ci["inst"].startswith("pop"):
                tokens = ci["inst"].split(" ")
                if len(tokens) != 2:
                    continue

                dest_reg = tokens[1]
                if dest_reg == reg:
                    return i
        return None

    def simplify_reg_obfs(self, code_info, reg, start, end):
        """
        Simplify register obfuscation block with the single instruction that
        uses the push/pop register
        """
        # Obfuscation starts with a push reg, reg manipulation followed by use of
        # reg and pop reg

        # Get just the instructions that manipulate the register
        bytecode = b""
        for i in range(start + 1, end -1):
            ci = code_info[i]
            bytecode += bytes(ci["bytes"])

        # Emulate code and get final value of reg
        val = emulate_reg_val(bytecode, reg)

        # Replace reg used in instruction with literal value
        ci = code_info[end - 1]

        # TODO: This is an ugly way to patch those instructions that use
        # partial register instead of the whole register e.g. CL instead of ECX
        reg_lowbyte = reg[1] + "l"
        if reg in ci["inst"]:
            patched_code = ci["inst"].replace(reg, hex(val))
        elif reg_lowbyte in ci["inst"]:
            patched_code = ci["inst"].replace(reg_lowbyte, hex(val & 0xff))

        # Assemble the code
        asm_bytes = assemble(patched_code)

        # Create new code info list and pad with NOPs
        patched_code_info = []
        patched_code_info.append(
            {
                "addr": code_info[start]["addr"],
                "bytes": asm_bytes,
                "inst": patched_code,
            }
        )

        nop_start = code_info[start]["addr"] + len(asm_bytes)
        nop_end = code_info[end]["addr"] + len(code_info[end]["bytes"])
        for i in range(nop_start, nop_end):
            patched_code_info.append(
                {
                    "addr": i,
                    "bytes":bytearray(b"\x90"),
                    "inst": "nop"
                }
            )

        return patched_code_info

    def fix_reg_obfs(self, code_info):
        """
        Loop though code and push and pops that span around 10 instructions
        - Emulate to get the register values
        - Replace instruction to use literal value
        - Replace the unneeded instructions with NOPs to be removed in a
          separate pass
        """

        # TODO: Still not detecting the following pattern
        # - When the instruction using the register is not immediately after
        #   the pop register, see function @ 0x29000

        # Store the last index that we fixed a register obfuscation block
        last_fixed = -1
        fixing = True

        while fixing:
            # Reset the fixing flag. We set to True if we simplified a register
            # obfuscation block so that we loop through the updated code to
            # replace other instances of the register obfuscated blocks
            fixing = False
            for i, ci in enumerate(code_info):

                # Skip instructions that we already checked
                if i <= last_fixed:
                    continue

                if ci["inst"].startswith("push"):
                    tokens = ci["inst"].split(" ")
                    if len(tokens) != 2:
                        continue

                    dest_reg = tokens[1]

                    # Find if there's a corresponding pop within the next 10
                    # instructions
                    end_i = self.find_reg_pop(code_info, i, dest_reg)
                    if end_i is None:
                        continue

                    # Check that instruction before pop uses the register
                    dest_reg_lowbyte = dest_reg[1] + "l"
                    if dest_reg not in code_info[end_i - 1]["inst"] and \
                        dest_reg_lowbyte not in code_info[end_i - 1]["inst"]:
                        continue

                    # Get the simplified code with nop padding
                    modified_code_info = self.simplify_reg_obfs(code_info,
                            dest_reg, i, end_i)

                    # Update the code
                    code_info = code_info[:i] + \
                        modified_code_info + \
                        code_info[end_i+1:]

                    fixing = True
                    last_fixed = i
                    break

        return code_info

## NOP cleanup funcs
    def remove_nops(self, code_info, start_va):
        """
        Disassemble and rewrite the code without NOPs
        """
        # TODO: This is probably better if we can working with basic blocks
        # instead of individual ASM instructions

        orig_bytes = b""
        for ci in code_info:
            orig_bytes += bytes(ci["bytes"])

        codes = self.md.disasm(orig_bytes, start_va)

        patched_bytes = b""
        new_ip = start_va

        addr_map = {}

        while True:
            try:
                i = next(codes)
            except StopIteration:
                break

            # Patch jmps, calls, leas to continue to redirect to the original
            # offsets since their instruction addresses have moved after removing
            # nops
            if i.mnemonic == "jmp":
                dest = self.handle_jump(i)
                ins_bytes = self.get_patch_force_jump_bytes(new_ip, dest)
            elif i.mnemonic == "call":
                ins_bytes, _ = self.handle_call(i, new_ip)
            elif i.mnemonic == "lea":
                ins_bytes, _ = self.handle_lea(i, new_ip)
            elif X86_GRP_BRANCH_RELATIVE in i.groups and X86_GRP_JUMP in i.groups:
                ins_bytes, dest = self.handle_conditional_jumps(i, new_ip)
            else:
                ins_bytes = i.bytes

            # Add instruction bytes if not nops
            if i.mnemonic != "nop":
                patched_bytes += ins_bytes

                addr_map[i.address] = new_ip

                # Update the new virtual address so that we can relocate
                # redirections correctly
                new_ip += i.size

            # We reach the end of the func, stop disassembly
            if i.mnemonic == "ret":
                break

        return patched_bytes, addr_map

    def fix_internal_jumps(self, code_bytes, addr_map, start_va):
        """
        Fix internal jumps so that they redirect to the correct destinations
        removing all the NOPs
        """
        codes = self.md.disasm(code_bytes, start_va)

        patched_bytes = b""
        new_ip = start_va

        while True:
            try:
                i = next(codes)
            except StopIteration:
                break

            # Patch internal jmps to the correct locations since the relative
            # offsets have changed after removing the nops
            if i.mnemonic == "jmp":
                dest = self.handle_jump(i)
                new_dest = addr_map.get(dest, None)
                if new_dest is not None:
                    ins_bytes = self.get_patch_force_jump_bytes(new_ip, new_dest)
                else:
                    ins_bytes = i.bytes
            elif X86_GRP_BRANCH_RELATIVE in i.groups and X86_GRP_JUMP in i.groups:
                ins_bytes, dest = self.handle_conditional_jumps(i, new_ip)
                new_dest = addr_map.get(dest, None)
                if new_dest is not None:
                    ins_bytes = self.get_patch_cond_jump_bytes(bytes(i.bytes), \
                        new_ip, new_dest)
            else:
                ins_bytes = i.bytes

            patched_bytes += ins_bytes

            # Update the new virtual address so that we can relocate
            # redirections correctly
            new_ip += i.size

            # We reach the end of the func, stop disassembly
            if i.mnemonic == "ret":
                break

        return patched_bytes

## Helpers for assembling and emulating

def assemble(code):
    """
    Assemble with keystone
    """
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # asm returns an array of ints and the number of statements processed
        code_ints, count = ks.asm(code)
        return bytearray(code_ints)
    except KsError as e:
        print("assembler failed: %s" % e)
        return b"", 0

def emulate_reg_val(bytecode, reg):
    """
    Emulate code block to get final value of a reg
    """
    # Initialize emulator in X86-32bit mode
    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    # Allocate and map 4096 bytes memory for code
    uc.mem_map(0, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

    # Write our code to the code address
    uc.mem_write(0, bytecode)

    uc.emu_start(0, len(bytecode))
    reg_aliases = {
        "eax": UC_X86_REG_EAX,
        "ebx": UC_X86_REG_EBX,
        "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX,
        "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI,
    }
    r = reg_aliases.get(reg, None)
    if r is not None:
        return uc.reg_read(r)
    return None

if __name__ == "__main__":
    cfg = {
        "disasm_size": 50,
        "max_insn": 9000,
        "patch_ext": ".patched1",
        "max_func_size": 0xb000,
        "max_funcs": 50,
    }

    d = Disasm(cfg)
    d.load("shellcode.bin")
    d.wipe_existing_code()

    # Disassemble all functions in the blob starting from the first byte
    d.start(0)

    d.cleanup()
