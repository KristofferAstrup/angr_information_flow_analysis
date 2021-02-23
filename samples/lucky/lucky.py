import angr
import monkeyhex
from angrutils import *
import sys
sys.path.append('../../')
from customutil import util

def main():
    proj = angr.Project('lucky_64.out', load_options={'auto_load_libs':False})

    #flag_chars = [claripy.BVS('%d' % i, 8) for i in range(input_len)]
    #flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    state = proj.factory.entry_state(args=["./lucky_64.out"], add_options=angr.options.unicorn)
    simgr = proj.factory.simgr(state)#, veritesting=True)
    cfg = proj.analyses.CFGEmulated(keep_state=True, normalize=True, fail_fast=True, starts=[simgr.active[0].addr], initial_state=state)

    #simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg))
    simgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=1024*2))
    #simgr.use_technique(angr.exploration_techniques.DFS())
    #simgr.use_technique(angr.exploration_techniques.LengthLimiter(100))

    simgr.explore(find=0x401222)#find=lambda s: b'lucky' in s.posix.dumps(1))

    # cdg = proj.analyses.CDG(cfg)
    # print("-")
    # ddg = proj.analyses.DDG(cfg)
    # print("-")
    # target_node = cfg.get_any_node(0x401222)
    # print("-")
    # bs = proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])
    # print(bs)

    util.write_stashes(simgr)

    return 0

if __name__ == "__main__":
    main()