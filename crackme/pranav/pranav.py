import angr
import monkeyhex
import base64
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('a.out', load_options={'auto_load_libs':False})

    sym_arg_size = 200
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)

    state = proj.factory.entry_state(args=['./a.out', arg0])

    # for byte in arg0.chop(8):
    #     state.add_constraints(byte >= '\x20') # ' '
    #     state.add_constraints(byte <= '\x7e') # '~'

    simgr = proj.factory.simgr(state, save_unconstrained=True)
    #cfg = proj.analyses.CFGFast()
    
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    # while simgr.active and not simgr.unconstrained:
    #     simgr.step()
    # if not simgr.unconstrained:
    #     print("Never constrained!")
    #s = simgr.unconstrained[0]
    #s.add_constraints(s.regs.rip == proj.loader.find_symbol('win').rebased_addr)
    
    simgr.explore(find=0x400926)

    util.write_stashes(simgr, [arg0])
    # if(simgr.found):
    #     print('--success--')
    #     for found in simgr.found:
    #         print("-----")
    #         print(found.addr)
    #         print(found.posix.dumps(0))
    #         print(found.posix.dumps(1))
    #         print(found.posix.dumps(2))
    #         print(found.solver.eval(arg0))
    #     print('-----------')
    
    return 0

if __name__ == "__main__":
    main()