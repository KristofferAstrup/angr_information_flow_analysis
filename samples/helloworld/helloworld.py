import angr
import monkeyhex
from angrutils import *
import sys
sys.path.append('../')
from information_flow_analysis import util

def main():
    proj = angr.Project('helloworld.out', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, fail_fast=True, starts=[simgr.active[0].addr], initial_state=state)

    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    simgr.explore(find=lambda s: b'hello' in s.posix.dumps(1))

    util.write_stashes(simgr)
    return 0

if __name__ == "__main__":
    main()