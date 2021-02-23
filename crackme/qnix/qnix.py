import angr
import monkeyhex
import base64
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('qvm32', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state, save_unconstrained=True)
    
    cfg = proj.analyses.CFGFast()
    #simgr.use_technique(angr.exploration_techniques.LengthLimiter(1000))
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*1))
    simgr.explore(find=0x8100014)#, avoid=lambda s: b'FAILED' in s.posix.dumps(1))
    
    util.write_stashes(simgr)
    return 0

if __name__ == "__main__":
    main()