import shutil
from malduck import rc4

from capstone import *

from unicorn import *
from unicorn.x86_const import *

class Emulator:
    def __init__(self):
        self.reg_aliases = {
            "rax": UC_X86_REG_RAX,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX,
            "rsi": UC_X86_REG_RSI,
            "rdi": UC_X86_REG_RDI,
            "rsp": UC_X86_REG_RSP,
            "rip": UC_X86_REG_RIP,
            "r8": UC_X86_REG_R8,
            "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12,
            "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14,
            "r15": UC_X86_REG_R15,
        }

    def load_bin(self, filename):
        self.code = b""
        with open(filename, "rb") as f:
            self.code = f.read()
        self.hooks = {}

    def disasm(self, mem, addr):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        return '\n'.join(['%s %s' % (i.mnemonic, i.op_str) for i in
            md.disasm(mem, addr)])

    def config(self, cfg):
        """
        Use a hardcoded dict and provide a example config in main
        """
        # TODO: Proper error checking required!
        self.code_addr = cfg.get("code_addr", 0)
        self.code_size = cfg.get("code_size", \
                (len(self.code) // 0x1000) * 0x1000 + 0x1000)

        # Set stack at the next 0x10000000 boundary
        self.stack_addr = (((self.code_addr + self.code_size) // 0x10000000) +
        1) * 0x10000000

        # Default to 1MB stack if unspecified
        self.stack_size = cfg.get("stack_size", 1024 * 1024 * 1)
        self.code_start = cfg.get("code_start", 0)
        self.code_end = cfg.get("code_end", -1)
        self.print_disasm = cfg.get("print_disasm", False)
        self.insn_hooks = cfg.get("insn_hooks", {})

    def start(self):
        # Initialize emulator in X86-64bit mode
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

        # Allocate and map memory for code and stack
        # NOTE that stack is not executable
        self.uc.mem_map(self.code_addr, self.code_size)
        self.uc.mem_map(self.stack_addr, self.stack_size, UC_PROT_READ | UC_PROT_WRITE)

        # Write our code to the code address
        self.uc.mem_write(self.code_addr, self.code)

        # Initialize machine registers. Stack pointer is in the middle of the
        # stack
        self.uc.reg_write(UC_X86_REG_RSP, self.stack_addr + self.stack_size // 2)

        # Trace all instructions with customized callback
        self.uc.hook_add(UC_HOOK_CODE, self.internal_hook)

        # Add instruction hooks
        for i, f in self.insn_hooks.items():
            # TODO: No error check to check that func is actually a func
            self.uc.hook_add(UC_HOOK_INSN, f, None, 1, 0, i)

        print("\nEmulation started at 0x%x" % self.code_start)
        self.stopping = False
        self.uc.emu_start(self.code_start, self.code_end)

    def internal_hook(self, uc, address, size, user_data):
        """
        This approach increases complexity but the encapsulation makes the
        calling code cleaner once we start adding more custom hooks
        """
        if self.stopping:
            uc.emu_stop()
            print("\nEmulation stopped at 0x%x" % address)
            return

        if self.print_disasm:
            print(hex(address))
            mem = uc.mem_read(address, size)
            dis = self.disasm(mem, address)
            print("%x: %s" % (address, dis))

        func = self.hooks.get(address, None)
        if func is not None:
            print("\n> Hook at %s" % hex(address))
            func(self)

        if address == self.code_end:
            uc.emu_stop()
            print("\nEmulation stopped at 0x%x" % self.code_end)

    def add_hook(self, addr, func):
        self.hooks[addr] = func

    # Helper methods to read and write registers and memory addresses
    def read_reg_val(self, reg):
        r = self.reg_aliases.get(reg, None)
        if r is not None:
            return self.uc.reg_read(r)
        else:
            print("ERR: Register not supported")

    def read_base_var(self, offset):
        return self.uc.reg_read(UC_X86_REG_RBP) + offset

    def read_stack_var(self, offset):
        return self.uc.reg_read(UC_X86_REG_RSP) + offset

    def read_mem(self, addr, length):
        return self.uc.mem_read(addr, length)

    def read_mem_as_addr(self, addr):
        """
        Reads 8 bytes from specified address and returns it as a memory address
        """
        mem = self.uc.mem_read(addr, 8)
        return int.from_bytes(mem[:8], byteorder='little', signed=False)

    def trigger_stop(self):
        # TODO: For unknown reason, calling emu_stop in insn callback doesn't
        # stop the emulator at times, set a flag and check it in the code hook
        self.stopping = True

# Print helpers
def hex_str(bs):
    """
    bs is a byte string
    """
    print(" ".join("%02x" % b for b in bs))

def hex_dump(buf):
    """
    Print hex values with ascii beside it like hex editor
    """
    current = 0
    length = len(buf)
    rounds = length // 0x10
    remain = length % 0x10
    for i in range(0, rounds):
        bs = buf[current:current+0x10]
        out = " ".join("%02x" % b for b in bs)
        out += "\t"
        out += "".join("%s" % convert_ascii(b) for b in bs)
        print(out)
        current += 0x10
    bs = buf[current:]

    out = " ".join("%02x" % b for b in bs)
    out += " ".join("  " for i in range(0, 0x10 - len(bs)))
    out += "\t"
    out += "".join("%s" % convert_ascii(b) for b in bs)
    print(out)

def convert_ascii(b):
    if b >= 0x20 and b < 0x7f:
        return chr(b)
    else:
        return '.'

class Patcher:
    def __init__(self):
        e = Emulator()
        self.e = e

        # Make a copy of file so that we can patch later
        src = "ch12_code.bin"
        dest = "ch12_code.autopatch"
        self.file = dest
        shutil.copyfile(src, dest)

        conf = {
            "code_addr": 0x0,
            "code_size": 0x100000,
            "code_start": 0xcfe,
            "code_end": 0xd0d,
            # Because we reinitialize the emulator after each patch, we keep
            # the stack as small as possible for performance reasons
            "stack_size": 0x1000,
            "print_disasm": False,
            "insn_hooks": {
                UC_X86_INS_IN: self.patch_in,
                UC_X86_INS_OUT: self.patch_out,
            }
        }

        while True:
            self.patched = False
            e.load_bin(dest)
            e.config(conf)
            e.start()

            if self.patched:
                print("Patched and restarting")
            else:
                print("No more patches, exiting")
                break

    def patch_in(self, uc, port, size, user_data):
        """
        Read the location, RC4 key and length to decrypt and patch
        """
        r9 = uc.reg_read(UC_X86_REG_R9)
        r8 = uc.reg_read(UC_X86_REG_R8)
        rip = uc.reg_read(UC_X86_REG_RIP)
        rc4_key = int.to_bytes(r8, byteorder="little", length=8)
        self.e.trigger_stop()
        self.decrypt_and_patch_in(rip, rc4_key, r9)
        self.patched = True

        # TODO: Required by Unicorn to return an integer value
        return 0

    def decrypt_and_patch_in(self, offset, key, buf_len):
        with open(self.file, "rb+") as f:
            # in instruction is 2 bytes so we start reading 2 bytes after
            f.seek(offset + 2)
            buf = f.read(buf_len)
            buf = rc4(key, buf)

            # Nop out the in instructions because they are not needed
            f.seek(offset)
            f.write(b"\x90" * 2)

            # Write decrypted instructions
            f.write(buf)

    def patch_out(self, uc, port, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)

        # Just nop and continue, we don't need to reset the emulation
        self.nop_out(rip)

    def nop_out(self, offset):
        with open(self.file, "rb+") as f:
            # Nop out the in instructions because they are not needed
            f.seek(offset)
            f.write(b"\x90" * 2)

if __name__ == "__main__":
    # This doesn't patch a few locations where the emulator is unable to reach
    # due to invalid cli args
    p = Patcher()
