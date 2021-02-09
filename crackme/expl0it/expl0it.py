import angr
import monkeyhex
from angrutils import *

def main():
    proj = angr.Project('crackme.exe', load_options={'auto_load_libs':False})

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, fail_fast=True, starts=[simgr.active[0].addr], initial_state=state)
    plot_cfg(cfg, "cfg", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  

    return 0

if __name__ == "__main__":
    main()