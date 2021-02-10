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
    simgr = proj.factory.simgr(state, save_unconstrained=True)

    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))
    
    simgr.explore(find=0x401298)

    util.write_stashes(simgr, [arg0])
    return 0

if __name__ == "__main__":
    main()