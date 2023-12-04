from capstone import *
from capstone.x86 import *

class Disasm:
    def __init__(self, cfg):
        self.disasm_size = cfg.get("disasm_size", 50)

    def load(self, filename):
        self.filename = filename
        self.f = open(self.filename, "rb")

        # Start in 16-bit mode for Real mode
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True

    def cleanup(self):
        if self.f is not None:
            self.f.close()

    def read_va(self, va, size=-1):
        read_len = size
        if read_len == -1:
            read_len == self.disasm_size

        self.f.seek(va)
        data = self.f.read(read_len)
        return data

    def get_codes(self, va, size=-1):
        data = self.read_va(va, size)
        return self.md.disasm(data, va)

    def disasm_block(self, va, size, print_disasm=True):
        """
        Disassemble a block of code sequentially for number of instructions
        specified by size
        """
        codes = self.get_codes(va, size)

        insn_count = 0
        prev_insns = [""] * 2
        while True:
            try:
                i = next(codes)
            except StopIteration:
                print("Aborting, no more code found")
                break

            if insn_count >= size:
                print("Aborting, reached instruction limit")
                break

            insn_count += 1

            if print_disasm:
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

            if self.is_protected_mode_switch(prev_insns):
                print("\nSwitching to 32 bit Protected Mode ...")
                self.md.mode = CS_MODE_32
                codes = self.get_codes(i.address + i.size)
            elif self.is_long_mode_switch(prev_insns):
                print("\nSwitching to 64 bit Long Mode ...")
                self.md.mode = CS_MODE_64
                codes = self.get_codes(i.address + i.size)

            prev_insns.pop(0)
            prev_insns.append(i.mnemonic + " " + i.op_str)

            if i.mnemonic == "ret" or i.mnemonic == "jmp":
                break

    def is_protected_mode_switch(self, insns):
        return self.check_mode_switch(insns, "cr0", 1)

    def is_long_mode_switch(self, insns):
        # This particular sample ORs with 0x80000000 because it sets the OR reg
        # to value of cr0 which is already set to 1 for the switch to Protected
        # mode
        if self.check_mode_switch(insns, "cr0", 0x80000000):
            return True

        # This is not really needed here but usually OR is with 0x80000001
        return self.check_mode_switch(insns, "cr0", 0x80000001)

    def check_mode_switch(self, insns, check_cr_reg, check_or_val):
        if len(insns) != 2:
            return False

        insn1 = insns[0]
        insn2 = insns[1]

        # TODO: We should really work with Capstone instructions instead of
        # messing around with text, but this is good enough for now

        # Code looks like:
        # or eax, 1
        # mov cr0, eax
        if insn1.startswith("or") and insn2.startswith("mov"):
            # Process or instruction
            tokens = insn1.replace("or","").replace(" ","").split(",")
            if len(tokens) != 2:
                return False
            or_reg = tokens[0]
            or_val = tokens[1]

            # Process mov instruction
            tokens = insn2.replace("mov","").replace(" ","").split(",")
            if len(tokens) != 2:
                return False
            mov_cr = tokens[0]
            mov_reg = tokens[1]

            if mov_reg == or_reg and \
                mov_cr == check_cr_reg and \
                int(or_val,16) == check_or_val:
                return True

        return False

if __name__ == "__main__":
    cfg = {
        "disasm_size": 50,
    }

    d = Disasm(cfg)
    d.load("ch12_code.bin")

    # This is actually not correct because it is not following calls and jumps
    # correctly, but it gives us the gist of the behaviour
    #
    # The code works for this example because the code performing mode
    # switching are immediately after the long jumps
    print("Starting in 16 bit Real mode")
    d.disasm_block(0x0, 50)

    # This should be disassembled in x64
    d.disasm_block(0xcf2, 50)
    d.cleanup()
