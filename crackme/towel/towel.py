import angr
import monkeyhex
import base64
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('MarsAnalytica', load_options={'auto_load_libs':False})
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    #simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))
    #simgr.explore(avoid=lambda s: b'ACCESS DENIED' in s.posix.dumps(1))
    #simgr.run()
    #util.write_stashes(simgr)
    return 0

if __name__ == "__main__":
    main()