import angr
import monkeyhex
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('simple_alt.out', load_options={'auto_load_libs':False})
    sym_arg_size = 4
    arg1 = claripy.BVS('arg1', 8*sym_arg_size)
    arg2 = claripy.BVS('arg2', 8*sym_arg_size)
    arg3 = claripy.BVS('arg3', 8*sym_arg_size)

    state = proj.factory.entry_state(args=['./simple_alt.out', arg1, arg2, arg3])
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, fail_fast=True, starts=[simgr.active[0].addr], initial_state=state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    simgr.explore(find=lambda s: b'Perfect' in s.posix.dumps(1))

    util.write_stashes(simgr, args=[arg1, arg2, arg3], input_write_stashes=["found"])

    return 0

if __name__ == "__main__":
    main()