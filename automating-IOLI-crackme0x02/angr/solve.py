import angr
import sys

def main(argv):
    path_to_binary = "crackme0x02"
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    print_succ_address = 0x8048453
    print_fail_address = 0x8048461
    simulation.explore(find=print_succ_address, avoid=print_fail_address)

    if simulation.found:
        solution_state = simulation.found[0]
        print("Flag: ", solution_state.posix.dumps(sys.stdin.fileno()))
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)
