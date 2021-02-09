import angr
import monkeyhex
from angrutils import *

def main():
    proj = angr.Project('crackme.exe', load_options={'auto_load_libs':False})

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGEmulated(keep_state=True, fail_fast=True, starts=[simgr.active[0].addr], initial_state=state)
    #plot_cfg(cfg, "cfg", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  

    simgr.use_technique(angr.exploration_techniques.DFS())
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    simgr.explore(find=0x401366)
    print('dump0:')
    print(simgr.found[0].posix.dumps(0).decode('UTF-8'))

    return 0

if __name__ == "__main__":
    main()