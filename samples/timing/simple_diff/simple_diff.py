import angr
import claripy
import sys
sys.path.append('../../../')
from customutil import util_out, util_analysis

def main():
    proj = angr.Project('./samples/timing/simple_diff/simple_diff.out', load_options={'auto_load_libs':False})

    sym_arg_size = 15
    arg0 = claripy.BVS('arg0', 8*sym_arg_size)
    state = proj.factory.entry_state(args=['./simple_diff.out', arg0])
    simgr = proj.factory.simulation_manager(state)
    for byte in arg0.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~'

    high_addrs = [0x401155, 0x401158]
    start_addr = 0x401149 #main entry block

    ifa = util_analysis.InformationFlowAnalysis(proj=proj,state=state,start=start_addr,high_addrs=high_addrs)
    for leak in ifa.find_covert_leaks():
        print(leak)
    pass

if __name__ == "__main__":
    main()
