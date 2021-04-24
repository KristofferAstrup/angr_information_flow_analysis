import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis, util_out

def main():
    proj = angr.Project('implicit_progress.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./implicit_progress.out', arg0])
    
    start_addr = 0x401149
    subject_addrs = [0x40119b]
    high_addrs = [0x00401155, 0x00401158]
    
    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs, subject_addrs=subject_addrs)
    leaks = ifa.find_all_leaks()
    return 0

if __name__ == "__main__":
    main()
