import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis

def main():
    proj = angr.Project('implicit2.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit2.out', arg0])
    simgr = proj.factory.simgr(state)

    start_addr = 0x401149
    high_addrs = [0x401155, 0x401158]
    subject_addrs = [0x401168, 0x40118a]
    
    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs, subject_addrs=subject_addrs)
    leaks = ifa.find_all_leaks()
    return 0
    
if __name__ == "__main__":
    main()
