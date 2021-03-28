import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x08048601
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)
  password2 = claripy.BVS('password2', 64)
  password3 = claripy.BVS('password3', 64)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0xA1BA1C0
  initial_state.memory.store(password0_address, password0)
  password1_address = 0xA1BA1C8
  initial_state.memory.store(password1_address, password1)
  password2_address = 0xA1BA1D0
  initial_state.memory.store(password2_address, password2)
  password3_address = 0xA1BA1D8
  initial_state.memory.store(password3_address, password3)

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

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution0 = solution_state.solver.eval(password0,cast_to=bytes)
    solution1 = solution_state.solver.eval(password1,cast_to=bytes)
    solution2 = solution_state.solver.eval(password2,cast_to=bytes)
    solution3 = solution_state.solver.eval(password3,cast_to=bytes)
    solution = bytes.decode(solution0, "UTF-8") + " " \
        + bytes.decode(solution1,"UTF-8") + " " \
        + bytes.decode(solution2, "UTF-8") + " " \
        + bytes.decode(solution3, "UTF-8")

    print (solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
