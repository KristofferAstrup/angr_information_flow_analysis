import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis, util_implicit

def main():
    proj = angr.Project('implicit3.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit3.out', arg0])
    simgr = proj.factory.simgr(state)

    high_addrs = [0x4011a6, 0x4011a9]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start="main",high_addrs=high_addrs)
    subject_addrs = ifa.find_and_add_subject_addrs("puts")
    ifa.draw_everything()
    #leaks = ifa.find_all_leaks()
    return 0
    
if __name__ == "__main__":
    main()