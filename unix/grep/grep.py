import angr
import monkeyhex
from angrutils import *

def main():
    proj = angr.Project('grep', load_options={'auto_load_libs':False})

    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    cfg = proj.analyses.CFGFast()
    plot_cfg(cfg, "cfg", "pdf", asminst=True, remove_imports=True, remove_path_terminator=True)  

    return 0

if __name__ == "__main__":
    main()