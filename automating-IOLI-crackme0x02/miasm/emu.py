from miasm.analysis.sandbox import Sandbox_Linux_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE

# Using sandbox is good as it provides a lot of useful diagnostic options like
# -b to print blocks, use -h to see other options
# Parse arguments
parser = Sandbox_Linux_x86_32.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Linux_x86_32(loc_db, options.filename, options, globals())

# Allocate arbitrary umemory page for local variables
stack_addr = 0x777000
stack_size = 0x1000
sb.jitter.vm.add_memory_page(
        stack_addr - stack_size, PAGE_READ | PAGE_WRITE,  b"\x00"*stack_size,
        "Stack for local vars")
sb.jitter.cpu.EBP = stack_addr

def print_flag(jitter):
    print("Flag =", jitter.cpu.EAX)
    # Stop emulation
    return False

# Setup callback as flag is in EAX at this address
sb.jitter.add_breakpoint(0x08048448, print_flag)

# Start emulation
entry_addr = 0x804842B
sb.run(entry_addr)
