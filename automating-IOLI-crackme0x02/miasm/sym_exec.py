from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_32
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.expression.simplifications import expr_simp

loc_db = LocationDB()
cont = Container.from_stream(open("crackme0x02", "rb"), loc_db)
machine = Machine(cont.arch)

# --- Disassemble --- #
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db, follow_call=True)

# Disassemble at the block that checks the key
entry_addr = 0x804842B
asmcfg = mdis.dis_multiblock(entry_addr)

# Write Graphviz
open("cfg.dot", "w").write(asmcfg.dot())

# --- Get IR --- #

lifter = LifterModelCall_x86_32(loc_db)
ircfg = lifter.new_ircfg()

first_block = list(asmcfg.blocks)[0]
lifter.add_asmblock_to_ircfg(first_block, ircfg)


# --- Symbolic execution --- #

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *

symb = SymbolicExecutionEngine(lifter, machine.mn.regs.regs_init)

# irDst contains the offset of next IR basic block to execute
irDst = symb.run_at(ircfg, entry_addr, step=False)
print("IR Dest = ", irDst)

# Provide symbolic context to irDst
expr_flag = ExprId("flag", 32)
result = symb.eval_expr(expr_simp(irDst.replace_expr({
    expr_simp(ExprMem(machine.mn.regs.EBP_init - ExprInt(0x4, 32), 32)):
    expr_flag,
    }
    )))
print("IR Dest Semantics = ", result)

# Dump the final state of symbolic execution
# symb.dump()
