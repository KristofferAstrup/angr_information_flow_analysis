import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis, util_out

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])
    simgr = proj.factory.simgr(state)

    start_addr = 0x40118f
    high_addrs = [0x40119b, 0x40119e]
    subject_addrs = [0x004011a2, 0x00401184, 0x004011bf]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs, subject_addrs=subject_addrs)
    leaks = ifa.find_all_leaks()
    return 0
    
if __name__ == "__main__":
    main()