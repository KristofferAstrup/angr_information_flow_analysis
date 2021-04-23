import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_analysis

def main():
    proj = angr.Project('flow_sensitivity.out', load_options={'auto_load_libs':False})
    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./flow_sensitivity.out', arg0])

    start_addr = 0x401149
    high_addrs = [0x401155, 0x401158]

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start_addr=start_addr,high_addrs=high_addrs)
    ifa.find_and_add_subject_addrs("puts")
    leaks = ifa.find_all_leaks()
    return
  
if __name__ == "__main__":
    main()