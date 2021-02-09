import angr
import monkeyhex
import sys
import angr.analyses.analysis
import claripy
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('happycat.exe', load_options={'auto_load_libs':False})
    
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)

    cfg = proj.analyses.CFGFast()
   
    print('------cfg-done------')
    #simgr.use_technique(angr.exploration_techniques.UniqueSearch())
    #simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))
    #simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))

    simgr.explore(avoid=lambda s: b'Incorrect' in s.posix.dumps(1))
    
    util.write_stashes(simgr, [])

    return 0

if __name__ == "__main__":
    main()