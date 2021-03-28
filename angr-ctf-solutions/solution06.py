import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x08048699
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)

  # Instead of telling the binary to write to the address of the memory
  # allocated with malloc, we can simply fake an address to any unused block of
  # memory and overwrite the pointer to the data. This will point the pointer
  # with the address of pointer_to_malloc_memory_address0 to fake_heap_address.
  # Be aware, there is more than one pointer! Analyze the binary to determine
  # global location of each pointer.
  # Note: by default, Angr stores integers in memory with big-endianness. To
  # specify to use the endianness of your architecture, use the parameter
  # endness=project.arch.memory_endness. On x86, this is little-endian.
  # (!)
  fake_heap_address0 = 0x0804A080 # Use padding2
  pointer_to_malloc_memory_address0 = 0x0ABCC8A4
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  fake_heap_address1 = 0x0804A088 # Use padding2
  pointer_to_malloc_memory_address1 = 0x0ABCC8AC
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

  # Store our symbolic values at our fake_heap_address. Look at the binary to
  # determine the offsets from the fake_heap_address where scanf writes.
  # (!)
  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    o = bytes.decode(stdout_output, "UTF-8")
    return o.find("Good Job") != -1

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    o = bytes.decode(stdout_output, "UTF-8")
    return o.find("Try again") != -1

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution = bytes.decode(solution0, "UTF-8") + " " \
        + bytes.decode(solution1,"UTF-8")

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
