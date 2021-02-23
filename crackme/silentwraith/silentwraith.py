import angr
import monkeyhex
import base64
from angrutils import *
import sys
sys.path.append('../../')
from customutil.util import *

def main():
    proj = angr.Project('lockcode', load_options={'auto_load_libs':False})

    sym_arg_size = 40
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)

    state = proj.factory.entry_state(args=['./lockcode', arg0])

    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGFast()
    
    #simgr.use_technique(angr.exploration_techniques.UniqueSearch())
    #simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))
    #simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    simgr.explore(avoid=lambda s: (b'failed' in s.posix.dumps(1)))
    write_stashes(simgr, args=[arg0])
    if(simgr.found):
        print('--success--')
        for found in simgr.found:
            print("-----")
            print(found.addr)
            print(found.posix.dumps(0))
            print(found.posix.dumps(1))
            print(found.posix.dumps(2))
            print(found.solver.eval(arg0))
        print('-----------')
    
    return 0

if __name__ == "__main__":
    main()