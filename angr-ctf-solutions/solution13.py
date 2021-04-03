# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc'])
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.

# Copied from scaffold01.py
import angr
import sys

def main(argv):
  path_to_binary = "13_angr_static_binary"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()

  malloc_address = 0x80591A0
  project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
  scanf_address = 0x804ED80
  project.hook(scanf_address, angr.SIM_PROCEDURES['libc']['scanf']())
  strcmp_address = 0x8048280
  project.hook(strcmp_address, angr.SIM_PROCEDURES['libc']['strcmp']())
  puts_address = 0x804F350
  project.hook(puts_address, angr.SIM_PROCEDURES['libc']['puts']())
  printf_address = 0x804ED40
  project.hook(printf_address, angr.SIM_PROCEDURES['libc']['printf']())
  main_address = 0x08048D10
  project.hook(main_address, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

  simulation = project.factory.simgr(initial_state)

  # Explore the binary, but this time, instead of only looking for a state that
  # reaches the print_good_address, also find a state that does not reach
  # will_not_succeed_address. The binary is pretty large, to save you some time,
  # everything you will need to look at is near the beginning of the address
  # space.
  # (!)
  print_good_address = 0x80489D9
  will_not_succeed_address = 0x080489C7
  simulation.explore(find=print_good_address, avoid=will_not_succeed_address)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)

