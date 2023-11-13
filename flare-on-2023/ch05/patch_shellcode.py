import os
import shutil

from capstone import *
from capstone.x86 import *

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

        # Write instruction bytes to file
        self.patch_code_info(code_info)

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

if __name__ == "__main__":
    cfg = {
        "disasm_size": 50,
        "max_insn": 9000,
        "patch_ext": ".patchedg",
        "max_func_size": 0xb000,
        "max_funcs": 50,
    }

    d = Disasm(cfg)
    d.load("shellcode.bin")
    d.wipe_existing_code()

    # Disassemble all functions in the blob starting from the first byte
    d.start(0)

    d.cleanup()
